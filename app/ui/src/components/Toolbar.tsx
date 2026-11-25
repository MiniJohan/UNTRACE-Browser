import { useEffect, useState, type RefObject } from "react";
import { api, errorText, type DownloadInfo, type TabInfo } from "../api";
import { connectionOf, isBlank } from "../util";
import { Back, BookmarkList, Close, Download, Forward, Gear, Info, Pulse, Reload, Star } from "./Icons";

export type Page = "browse" | "settings" | "diagnostics" | "data" | "activity" | "welcome" | "about";
export type Panel = "site" | "downloads" | "bookmarks" | null;

type Props = {
  tab: TabInfo | undefined;
  page: Page;
  panel: Panel;
  downloads: DownloadInfo[];
  addressRef: RefObject<HTMLInputElement | null>;
  onPanel: (p: Panel) => void;
  onPage: (p: Page) => void;
  /** M9: a newer UNTRACE is waiting to be installed. */
  updateVersion: string | null;
  /** D-055: the page is bookmarked; the star adds it or opens its bookmark. */
  bookmarked: boolean;
  onBookmark: () => void;
};

export function Toolbar({ tab, page, panel, downloads, addressRef, onPanel, onPage, updateVersion, bookmarked, onBookmark }: Props) {
  const url = tab?.url ?? "";
  const shown = isBlank(url) ? "" : url;
  const [value, setValue] = useState(shown);
  const [editing, setEditing] = useState(false);
  const [hint, setHint] = useState<string | null>(null);

  useEffect(() => {
    if (!editing) setValue(shown);
  }, [shown, editing]);

  useEffect(() => {
    if (!hint) return;
    const t = setTimeout(() => setHint(null), 5000);
    return () => clearTimeout(t);
  }, [hint]);

  const submit = async () => {
    try {
      await api.navigate(value);
      setHint(null);
      onPage("browse");
      addressRef.current?.blur();
      await api.focusContent();
    } catch (e) {
      setHint(errorText(e));
    }
  };

  const insecure = connectionOf(url) === "http";
  const canBookmark = !!tab && !tab.newTabPage && !tab.interstitial && (connectionOf(url) === "https" || insecure);
  const active = downloads.filter((d) => d.state === "in_progress").length;

  return (
    <div className="toolbar">
      <div className="nav-buttons">
        <button className="icon-btn" aria-label="Back (Alt+Left)" title="Back" disabled={!tab?.canGoBack} onClick={() => api.back()}>
          <Back />
        </button>
        <button className="icon-btn" aria-label="Forward (Alt+Right)" title="Forward" disabled={!tab?.canGoForward} onClick={() => api.forward()}>
          <Forward />
        </button>
        {tab?.loading ? (
          <button className="icon-btn" aria-label="Stop" title="Stop" onClick={() => api.stop()}>
            <Close />
          </button>
        ) : (
          <button className="icon-btn" aria-label="Reload (F5)" title="Reload" disabled={!tab} onClick={() => api.reload()}>
            <Reload />
          </button>
        )}
      </div>

      <div className={`address${editing ? " editing" : ""}${hint ? " has-hint" : ""}`}>
        {tab?.temporary && !editing && (
          <span className="tag temp" title="Nothing from this tab is kept after the last temporary tab closes">
            Temporary
          </span>
        )}
        {insecure && !editing && <span className="tag danger">Not secure</span>}
        <input
          ref={addressRef}
          className="address-input"
          spellCheck={false}
          autoComplete="off"
          aria-label="Address"
          placeholder="Search or enter address"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onFocus={(e) => {
            setEditing(true);
            const el = e.currentTarget;
            requestAnimationFrame(() => el.select());
          }}
          onBlur={() => setEditing(false)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              submit();
            } else if (e.key === "Escape") {
              e.preventDefault();
              setValue(shown);
              setHint(null);
              e.currentTarget.blur();
              api.focusContent().catch(() => {});
            }
          }}
        />
        {hint && (
          <span className="address-hint" role="alert">
            {hint}
          </span>
        )}
        {canBookmark && !editing && (
          <button
            className={`icon-btn star-btn${bookmarked ? " on" : ""}`}
            aria-label={bookmarked ? "Edit bookmark (Ctrl+D)" : "Bookmark this page (Ctrl+D)"}
            aria-pressed={bookmarked}
            title={bookmarked ? "Edit bookmark (Ctrl+D)" : "Bookmark this page (Ctrl+D)"}
            onMouseDown={(e) => e.preventDefault()}
            onClick={onBookmark}
          >
            <Star filled={bookmarked} />
          </button>
        )}
      </div>

      <div className="tool-buttons">
        <button
          className={`icon-btn${panel === "bookmarks" && page === "browse" ? " on" : ""}`}
          aria-label="Bookmarks"
          aria-pressed={panel === "bookmarks" && page === "browse"}
          title="Bookmarks"
          onClick={() => {
            onPage("browse");
            onPanel(panel === "bookmarks" ? null : "bookmarks");
          }}
        >
          <BookmarkList />
        </button>
        {downloads.length > 0 && (
          <button
            className={`icon-btn${panel === "downloads" && page === "browse" ? " on" : ""}${active ? " busy" : ""}`}
            aria-label={active ? `Downloads (${active} in progress)` : "Downloads"}
            aria-pressed={panel === "downloads" && page === "browse"}
            title="Downloads"
            onClick={() => {
              onPage("browse");
              onPanel(panel === "downloads" ? null : "downloads");
            }}
          >
            <Download />
          </button>
        )}
        <button
          className={`icon-btn${panel === "site" && page === "browse" ? " on" : ""}`}
          aria-label="About this page"
          aria-pressed={panel === "site" && page === "browse"}
          title="About this page"
          onClick={() => {
            onPage("browse");
            onPanel(panel === "site" ? null : "site");
          }}
        >
          <Info />
        </button>
        {updateVersion && (
          <button
            className="btn small-btn update-btn"
            title={`UNTRACE ${updateVersion} is available. Open Diagnostics to install it.`}
            onClick={() => onPage("diagnostics")}
          >
            Update
          </button>
        )}
        <button
          className={`icon-btn${page === "diagnostics" ? " on" : ""}`}
          aria-label="Diagnostics"
          aria-pressed={page === "diagnostics"}
          title="Diagnostics"
          onClick={() => onPage(page === "diagnostics" ? "browse" : "diagnostics")}
        >
          <Pulse />
        </button>
        <button
          className={`icon-btn${page === "settings" ? " on" : ""}`}
          aria-label="Settings (Ctrl+,)"
          aria-pressed={page === "settings"}
          title="Settings"
          onClick={() => onPage(page === "settings" ? "browse" : "settings")}
        >
          <Gear />
        </button>
      </div>
    </div>
  );
}
