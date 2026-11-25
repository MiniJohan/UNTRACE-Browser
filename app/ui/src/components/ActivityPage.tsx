import { useCallback, useEffect, useMemo, useState } from "react";
import { api, errorText } from "../api";

type Entry = { ts: string; event: string; details: string };

/** One log line, as stored (JSON): when, what, and the rest. */
function parse(raw: string): Entry {
  try {
    const v = JSON.parse(raw) as Record<string, unknown>;
    const { ts, event, ...rest } = v;
    const details = Object.entries(rest)
      .map(([k, x]) => `${k}: ${typeof x === "string" ? x : JSON.stringify(x)}`)
      .join(" · ");
    return { ts: String(ts ?? ""), event: String(event ?? "?"), details };
  } catch {
    return { ts: "", event: "unreadable", details: raw };
  }
}

/** The activity log (M7): every entry, filterable by kind, with export and clear. It never
 * contains addresses or sites. */
export function ActivityPage({ onBack }: { onBack: () => void }) {
  const [entries, setEntries] = useState<Entry[] | null>(null);
  const [kind, setKind] = useState("all");
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(() => {
    api
      .auditEntries()
      .then((lines) => setEntries(lines.map(parse).reverse()))
      .catch((e) => setNote(errorText(e)));
  }, []);
  useEffect(load, [load]);

  const kinds = useMemo(() => [...new Set((entries ?? []).map((e) => e.event))].sort(), [entries]);
  const shown = (entries ?? []).filter((e) => kind === "all" || e.event === kind);

  const exportLog = async () => {
    setNote(null);
    try {
      const path = await api.auditExport();
      setNote(path ? `Saved to ${path}.` : null);
    } catch (e) {
      setNote(errorText(e));
    }
    load();
  };

  const clear = async () => {
    setNote(null);
    try {
      await api.clearAudit();
      setNote("Cleared. The log now records only that it was cleared.");
    } catch (e) {
      setNote(errorText(e));
    }
    load();
  };

  return (
    <div className="page">
      <div className="page-inner">
        <div className="page-head">
          <h1>Activity log</h1>
          <button className="btn" onClick={onBack}>Back to Diagnostics</button>
        </div>
        <p className="muted">
          What UNTRACE did and changed: settings, list updates, clearing, checks and errors. It never records addresses
          or sites. It is kept on this computer only, up to about 1 MB (the oldest half is dropped when it is full).
        </p>
        <section className="card">
          <div className="page-head">
            <select className="select" value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Show entries of kind">
              <option value="all">All entries ({entries?.length ?? 0})</option>
              {kinds.map((k) => (
                <option key={k} value={k}>
                  {k.replace(/_/g, " ")} ({(entries ?? []).filter((e) => e.event === k).length})
                </option>
              ))}
            </select>
            <div className="inline-form">
              <button className="btn" onClick={exportLog}>Export…</button>
              <button className="btn" onClick={clear}>Clear</button>
            </div>
          </div>
          {note && <p className="small" role="status">{note}</p>}
          {entries === null ? (
            <p className="muted">Reading…</p>
          ) : shown.length === 0 ? (
            <p className="muted">No entries.</p>
          ) : (
            <div className="audit">
              {shown.map((e, i) => (
                <div className="audit-line" key={i}>
                  <span className="audit-ts">{e.ts.replace("T", " ").replace("Z", "")}</span>
                  <span className="audit-ev">{e.event.replace(/_/g, " ")}</span>
                  <span className="audit-rest">{e.details}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
