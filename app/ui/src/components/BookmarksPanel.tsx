import { useEffect, useMemo, useRef, useState } from "react";
import { api, errorText, type Bookmark, type BookmarkItem, type BookmarksView, type TabInfo } from "../api";
import { hostOf } from "../util";
import { Chevron, Close, Edit, Folder, Plus } from "./Icons";

type Located = { item: BookmarkItem; folder: number | null; index: number; siblings: number };

function locate(items: BookmarkItem[], id: number): Located | null {
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    if (it.id === id) return { item: it, folder: null, index: i, siblings: items.length };
    if (it.kind === "folder") {
      const j = it.items.findIndex((b) => b.id === id);
      if (j >= 0) return { item: it.items[j], folder: it.id, index: j, siblings: it.items.length };
    }
  }
  return null;
}

/** The page's own icon if it was saved with the bookmark, otherwise its first letter. */
export function BookmarkIcon({ b }: { b: Bookmark }) {
  if (b.icon) return <img className="bm-icon" src={b.icon} alt="" />;
  const letter = (hostOf(b.url).replace(/^www\./, "") || b.title || "?").charAt(0).toUpperCase();
  return (
    <span className="bm-icon bm-letter" aria-hidden="true">
      {letter}
    </span>
  );
}

function open(url: string, newTab: boolean) {
  const go = () => api.navigate(url).then(() => api.focusContent());
  (newTab ? api.tabNew().then(go) : go()).catch(() => {});
}

type Props = {
  view: BookmarksView | null;
  loadError: string | null;
  onView: (v: BookmarksView) => void;
  /** The bookmark or folder being edited (set when the star adds or finds one). */
  editId: number | null;
  onEdit: (id: number | null) => void;
  /** A message from the star or Ctrl+D (for example: this page cannot be bookmarked). */
  message: string | null;
  tab: TabInfo | undefined;
  onClose: () => void;
};

export function BookmarksPanel({ view, loadError, onView, editId, onEdit, message, tab, onClose }: Props) {
  const [query, setQuery] = useState("");
  const [openFolders, setOpenFolders] = useState<Set<number>>(new Set());
  const [note, setNote] = useState<{ text: string; error: boolean } | null>(null);
  const [newFolder, setNewFolder] = useState<string | null>(null);
  const [confirmAll, setConfirmAll] = useState(false);

  useEffect(() => {
    if (message) setNote({ text: message, error: true });
  }, [message]);

  const items = view?.items ?? [];
  const folders = items.filter((i) => i.kind === "folder");

  // Show the bookmark being edited inside its folder.
  useEffect(() => {
    if (editId === null || !view) return;
    const at = locate(view.items, editId);
    if (at?.folder != null) setOpenFolders((s) => new Set(s).add(at.folder as number));
  }, [editId, view]);

  const run = async (p: Promise<BookmarksView>) => {
    try {
      onView(await p);
      setNote(null);
      return true;
    } catch (e) {
      setNote({ text: errorText(e), error: true });
      return false;
    }
  };

  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return null;
    const out: { b: Bookmark; folder: string | null }[] = [];
    for (const it of items) {
      const list = it.kind === "folder" ? it.items.map((b) => ({ b, folder: it.title })) : [{ b: it, folder: null }];
      for (const m of list) {
        if (m.b.title.toLowerCase().includes(q) || m.b.url.toLowerCase().includes(q)) out.push(m);
      }
    }
    return out;
  }, [items, query]);

  const importFile = async () => {
    try {
      const r = await api.bookmarksImport();
      if (!r) return;
      onView(r.view);
      const { added, foldersAdded, duplicates, unsupported, overLimit } = r.report;
      const parts = [`Imported ${added} bookmark${added === 1 ? "" : "s"}${foldersAdded ? ` into ${foldersAdded} new folder${foldersAdded === 1 ? "" : "s"}` : ""}.`];
      if (duplicates) parts.push(`${duplicates} already bookmarked.`);
      if (unsupported) parts.push(`${unsupported} skipped: not web addresses (scripts, files or browser pages).`);
      if (overLimit) parts.push(`${overLimit} skipped: over the limit of ${r.view.max} bookmarks.`);
      setNote({ text: parts.join(" "), error: false });
    } catch (e) {
      setNote({ text: errorText(e), error: true });
    }
  };

  const exportFile = async () => {
    try {
      const path = await api.bookmarksExport();
      if (path) setNote({ text: `Saved to ${path}`, error: false });
    } catch (e) {
      setNote({ text: errorText(e), error: true });
    }
  };

  const row = (b: Bookmark, folderName: string | null = null) =>
    editId === b.id ? (
      <EditForm key={b.id} id={b.id} view={view!} tab={tab} onDone={() => onEdit(null)} run={run} />
    ) : (
      <li key={b.id} className="bm-row">
        <button
          className="bm-open"
          title={b.url}
          onClick={(e) => open(b.url, e.ctrlKey)}
          onAuxClick={(e) => {
            if (e.button === 1) open(b.url, true);
          }}
        >
          <BookmarkIcon b={b} />
          <span className="bm-text">
            <span className="bm-title">{b.title}</span>
            <span className="bm-host">{folderName ? `${folderName} · ${hostOf(b.url)}` : hostOf(b.url)}</span>
          </span>
        </button>
        <button className="icon-btn bm-edit-btn" aria-label={`Edit ${b.title}`} title="Edit" onClick={() => onEdit(b.id)}>
          <Edit />
        </button>
      </li>
    );

  return (
    <aside className="side-panel bookmarks-panel" aria-label="Bookmarks">
      <header className="panel-head">
        <h2>Bookmarks</h2>
        <button className="icon-btn" aria-label="Close panel" onClick={onClose}>
          <Close />
        </button>
      </header>

      {loadError && <p className="notice danger">{loadError}</p>}
      {note && (
        <p className={`note${note.error ? " danger" : ""}`} role="status">
          {note.text}
        </p>
      )}

      {view && (
        <>
          <input
            className="text-input bm-search"
            type="search"
            placeholder="Search bookmarks"
            aria-label="Search bookmarks"
            spellCheck={false}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />

          {view.count === 0 && folders.length === 0 && (
            <p className="muted">
              No bookmarks yet. Press the star in the address bar, or Ctrl+D, to bookmark the page you are on.
            </p>
          )}

          {matches ? (
            <ul className="bm-list">
              {matches.length === 0 && <li className="muted small">Nothing matches.</li>}
              {matches.map((m) => row(m.b, m.folder))}
            </ul>
          ) : (
            <ul className="bm-list">
              {items.map((it) =>
                it.kind === "bookmark" ? (
                  row(it)
                ) : editId === it.id ? (
                  <EditForm key={it.id} id={it.id} view={view} tab={tab} onDone={() => onEdit(null)} run={run} />
                ) : (
                  <li key={it.id} className="bm-folder">
                    <div className="bm-row">
                      <button
                        className="bm-open"
                        aria-expanded={openFolders.has(it.id)}
                        onClick={() =>
                          setOpenFolders((s) => {
                            const n = new Set(s);
                            if (n.has(it.id)) n.delete(it.id);
                            else n.add(it.id);
                            return n;
                          })
                        }
                      >
                        <span className="bm-icon bm-folder-icon">
                          <Folder />
                        </span>
                        <span className="bm-text">
                          <span className="bm-title">{it.title}</span>
                          <span className="bm-host">
                            {it.items.length} bookmark{it.items.length === 1 ? "" : "s"}
                          </span>
                        </span>
                        <Chevron open={openFolders.has(it.id)} />
                      </button>
                      <button className="icon-btn bm-edit-btn" aria-label={`Edit folder ${it.title}`} title="Edit" onClick={() => onEdit(it.id)}>
                        <Edit />
                      </button>
                    </div>
                    {openFolders.has(it.id) && (
                      <ul className="bm-list bm-inner">
                        {it.items.length === 0 && <li className="muted small">Empty. Move bookmarks here with Edit.</li>}
                        {it.items.map((b) => row(b))}
                      </ul>
                    )}
                  </li>
                ),
              )}
            </ul>
          )}

          <div className="bm-footer">
            {newFolder === null ? (
              <button className="btn small-btn" onClick={() => setNewFolder("")}>
                <Plus size={12} /> New folder
              </button>
            ) : (
              <form
                className="inline-form"
                onSubmit={async (e) => {
                  e.preventDefault();
                  try {
                    const r = await api.bookmarkFolderAdd(newFolder);
                    onView(r.view);
                    setNewFolder(null);
                    setNote(null);
                  } catch (err) {
                    setNote({ text: errorText(err), error: true });
                  }
                }}
              >
                <input
                  className="text-input short"
                  autoFocus
                  placeholder="Folder name"
                  aria-label="New folder name"
                  value={newFolder}
                  onChange={(e) => setNewFolder(e.target.value)}
                  onKeyDown={(e) => e.key === "Escape" && setNewFolder(null)}
                />
                <button className="btn small-btn primary" type="submit">
                  Add
                </button>
                <button className="btn small-btn" type="button" onClick={() => setNewFolder(null)}>
                  Cancel
                </button>
              </form>
            )}
            <div className="bm-file-actions">
              <button className="btn small-btn" onClick={importFile}>
                Import…
              </button>
              <button className="btn small-btn" onClick={exportFile} disabled={view.count === 0}>
                Export…
              </button>
            </div>
          </div>

          <p className="muted small">
            Bookmarks are kept only on this computer, also those added from temporary tabs, and deleting browsing data
            does not remove them. A bookmark's icon is the one its page showed when you added it; UNTRACE never fetches
            icons. Import and export use the bookmarks file (HTML) that Chrome, Edge and Firefox read and write.
          </p>

          {view.count + folders.length > 0 &&
            (confirmAll ? (
              <div className="notice danger bm-confirm">
                <span>
                  Delete all {view.count} bookmark{view.count === 1 ? "" : "s"} and {folders.length} folder
                  {folders.length === 1 ? "" : "s"}? This cannot be undone. Export them first to keep a copy.
                </span>
                <div className="inline-form">
                  <button
                    className="btn small-btn"
                    onClick={async () => {
                      if (await run(api.bookmarksDeleteAll())) onEdit(null);
                      setConfirmAll(false);
                    }}
                  >
                    Delete all
                  </button>
                  <button className="btn small-btn" onClick={() => setConfirmAll(false)}>
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <button className="btn small-btn bm-delete-all" onClick={() => setConfirmAll(true)}>
                Delete all bookmarks…
              </button>
            ))}
        </>
      )}
    </aside>
  );
}

function EditForm({
  id,
  view,
  tab,
  onDone,
  run,
}: {
  id: number;
  view: BookmarksView;
  tab: TabInfo | undefined;
  onDone: () => void;
  run: (p: Promise<BookmarksView>) => Promise<boolean>;
}) {
  const at = locate(view.items, id);
  const isFolder = at?.item.kind === "folder";
  const [title, setTitle] = useState(at?.item.title ?? "");
  const [url, setUrl] = useState(at?.item.kind === "bookmark" ? at.item.url : "");
  const [folder, setFolder] = useState<number | null>(at?.folder ?? null);
  const [confirm, setConfirm] = useState(false);
  const titleRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    titleRef.current?.focus();
    titleRef.current?.select();
  }, []);

  if (!at) return null;
  const folders = view.items.filter((i) => i.kind === "folder");
  const fromTemporary = !isFolder && tab?.temporary && at.item.kind === "bookmark" && at.item.url === tab.url;

  const save = async () => {
    const ok = await run(api.bookmarkEdit(id, title, isFolder ? null : url));
    if (ok && !isFolder && folder !== at.folder) {
      if (!(await run(api.bookmarkMove(id, folder, 1_000_000)))) return;
    }
    if (ok) onDone();
  };
  const move = (delta: number) => run(api.bookmarkMove(id, at.folder, at.index + delta));
  const count = at.item.kind === "folder" ? at.item.items.length : 0;

  return (
    <li className="bm-edit">
      <form
        className="sub-form"
        onSubmit={(e) => {
          e.preventDefault();
          save();
        }}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            onDone();
          }
        }}
      >
        <label className="small muted" htmlFor={`bm-title-${id}`}>
          {isFolder ? "Folder name" : "Name"}
        </label>
        <input id={`bm-title-${id}`} ref={titleRef} className="text-input" value={title} onChange={(e) => setTitle(e.target.value)} />
        {!isFolder && (
          <>
            <label className="small muted" htmlFor={`bm-url-${id}`}>
              Address
            </label>
            <input
              id={`bm-url-${id}`}
              className="text-input mono"
              spellCheck={false}
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
            <label className="small muted" htmlFor={`bm-folder-${id}`}>
              Folder
            </label>
            <select
              id={`bm-folder-${id}`}
              className="select"
              value={folder ?? ""}
              onChange={(e) => setFolder(e.target.value === "" ? null : Number(e.target.value))}
            >
              <option value="">No folder</option>
              {folders.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.title}
                </option>
              ))}
            </select>
          </>
        )}
        {fromTemporary && <p className="note">This bookmark stays after the temporary tab closes.</p>}
        <div className="bm-edit-actions">
          <button className="btn small-btn primary" type="submit">
            Done
          </button>
          <button className="btn small-btn" type="button" disabled={at.index === 0} onClick={() => move(-1)} title="Move up">
            Up
          </button>
          <button
            className="btn small-btn"
            type="button"
            disabled={at.index >= at.siblings - 1}
            onClick={() => move(1)}
            title="Move down"
          >
            Down
          </button>
          {confirm ? (
            <button
              className="btn small-btn danger"
              type="button"
              onClick={async () => {
                if (await run(api.bookmarkRemove(id))) onDone();
              }}
            >
              {isFolder && count > 0 ? `Remove folder and ${count} bookmark${count === 1 ? "" : "s"}` : "Confirm remove"}
            </button>
          ) : (
            <button className="btn small-btn" type="button" onClick={() => setConfirm(true)}>
              Remove
            </button>
          )}
        </div>
      </form>
    </li>
  );
}
