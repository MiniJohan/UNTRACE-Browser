import { useCallback, useEffect, useState } from "react";
import { api, errorText, type CookieSite, type DataItem } from "../api";
import { formatBytes } from "../util";

/** Sites with cookies in normal tabs, read from the engine, each deletable. */
function CookieSites({ onChanged }: { onChanged: () => void }) {
  const [sites, setSites] = useState<CookieSite[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [notes, setNotes] = useState<Record<string, string>>({});

  const load = useCallback(() => {
    api
      .cookieSites()
      .then((s) => {
        setSites(s);
        setError(null);
      })
      .catch((e) => setError(errorText(e)));
  }, []);
  useEffect(load, [load]);

  const remove = async (site: string) => {
    try {
      const left = await api.deleteSiteData(site);
      setNotes((n) => ({ ...n, [site]: left === 0 ? "Deleted (checked: no cookies left)." : `${left} cookie(s) remain.` }));
    } catch (e) {
      setNotes((n) => ({ ...n, [site]: errorText(e) }));
    }
    load();
    onChanged();
  };

  const shown = (sites ?? []).filter((s) => s.site.includes(filter.trim().toLowerCase()));
  return (
    <section className="card">
      <h2>Cookies and site data by site</h2>
      <p className="muted small">
        Sites that stored cookies in normal tabs, as the engine reports them. Deleting a site also removes its local
        storage, IndexedDB and service workers. Sites that keep data without any cookie are not listed; “Delete all”
        above removes those too.
      </p>
      {error && <p className="note danger">{error}</p>}
      {sites && sites.length > 8 && (
        <input
          className="text-input"
          placeholder="Filter sites"
          aria-label="Filter sites"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      )}
      {sites === null && !error && <p className="muted small">Reading cookies…</p>}
      {sites && sites.length === 0 && <p className="muted small">No site has cookies stored.</p>}
      {shown.length > 0 && (
        <ul className="perm-list sites">
          {shown.map((s) => (
            <li key={s.site}>
              <span className="mono" title={s.hosts.join(", ")}>
                {s.site}
              </span>
              <span className="muted small">
                {s.cookies} cookie{s.cookies === 1 ? "" : "s"}
                {notes[s.site] && <> · {notes[s.site]}</>}
              </span>
              <button className="btn small-btn" onClick={() => remove(s.site)}>
                Delete
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function DataPage() {
  const [items, setItems] = useState<DataItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, { text: string; ok: boolean }>>({});
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(() => {
    api
      .dataInventory()
      .then(setItems)
      .catch((e) => setError(errorText(e)));
  }, []);
  useEffect(load, [load]);

  const clear = async (item: DataItem) => {
    setBusy(item.id);
    try {
      const text = await api.clearData(item.id);
      setNotes((n) => ({ ...n, [item.id]: { text, ok: true } }));
    } catch (e) {
      setNotes((n) => ({ ...n, [item.id]: { text: errorText(e), ok: false } }));
    } finally {
      setBusy(null);
      load();
    }
  };

  return (
    <div className="page">
      <div className="page-inner">
        <h1>Your data</h1>
        <p className="muted">
          Everything UNTRACE and its browser engine keep on this computer, where, how much and for how long. Nothing here
          is ever sent anywhere.
        </p>
        {error && <p className="notice danger">{error}</p>}
        {items === null && !error && <p className="muted">Measuring…</p>}
        {items && (
          <section className="card">
            {items.map((it) => (
              <div className="row data-row" key={it.id}>
                <div className="row-text">
                  <div className="row-title">
                    {it.title}
                    {it.bytes !== null && <span className="muted small"> · {formatBytes(it.bytes)}</span>}
                  </div>
                  <div className="row-desc">{it.what}</div>
                  <div className="row-state">{it.retention}</div>
                  {it.location && <div className="row-limits mono">{it.location}</div>}
                  {notes[it.id] && (
                    <div className={`note${notes[it.id].ok ? "" : " danger"}`} role="status">
                      {notes[it.id].text}
                    </div>
                  )}
                </div>
                {it.action && (
                  <button className="btn" disabled={busy !== null} onClick={() => clear(it)}>
                    {busy === it.id ? "Working…" : it.action}
                  </button>
                )}
              </div>
            ))}
          </section>
        )}
        <CookieSites onChanged={load} />
      </div>
    </div>
  );
}
