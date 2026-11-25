import { useCallback, useEffect, useState } from "react";
import {
  api,
  errorText,
  onAppUpdate,
  onSelfCheckDone,
  type AppUpdateStatus,
  type Diagnostics,
  type HostRecord,
  type NetworkCheck,
  type NetworkReport,
  type SelfCheckLast,
} from "../api";
import { Check, Cross, Question } from "./Icons";

function auditLine(raw: string): { ts: string; event: string; rest: string } {
  try {
    const { ts, event, ...rest } = JSON.parse(raw) as Record<string, unknown>;
    const fields = Object.entries(rest)
      .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
      .join("  ");
    return { ts: String(ts ?? ""), event: String(event ?? ""), rest: fields };
  } catch {
    return { ts: "", event: "unreadable", rest: "" };
  }
}

const kb = (n: number) => `${(n / 1024).toFixed(1)} KB`;

function exitText(d: Diagnostics): string {
  const r = d.lastExitClear;
  const what = (k: { cache: boolean; siteData: boolean }) =>
    [k.cache && "cache", k.siteData && "cookies and site data"].filter(Boolean).join(" and ") || "nothing";
  const start = d.startClear ? ` This start: ${what(d.startClear)} deleted before the first page, because the last exit did not finish.` : "";
  if (!r) return `Nothing was set to be deleted when UNTRACE last closed.${start}`;
  const when = new Date(r.at * 1000).toLocaleString();
  switch (r.state) {
    case "done":
      return `Last exit (${when}): ${what(r.kinds)} deleted${r.cookiesLeft !== null ? `; ${r.cookiesLeft} cookies left (read back)` : ""}.${start}`;
    case "pending":
      return `The last session ended without closing normally; ${what(r.kinds)} was owed.${start}`;
    default:
      return `Last exit (${when}): deleting ${what(r.kinds)} ${r.state === "timed_out" ? "took too long" : "failed"}${r.detail ? ` (${r.detail})` : ""}.${start}`;
  }
}

const VIA: Record<string, string> = { encrypted: "encrypted", windows: "Windows", literal: "IP address", test: "self-check" };

function checkText(c: NetworkCheck | null): string {
  switch (c?.state) {
    case "passed":
      return `Passed at start (${c.ms} ms): a request from the engine reached the network layer with this launch's credentials.`;
    case "failed":
      return `Failed: ${c.reason}`;
    case "pending":
      return "Checking…";
    case "off":
      return "Not needed: the network layer is off.";
    default:
      return "Not run yet.";
  }
}

/** DNS on this computer, the network layer, and the hosts it contacted this session. */
function NetworkSection({ report: n, onChanged }: { report: NetworkReport; onChanged: () => void }) {
  const [showHosts, setShowHosts] = useState(false);
  // UNTRACE's own check names (".untrace.invalid") are not part of either list.
  const own = (h: HostRecord) => h.host.endsWith(".untrace.invalid");
  const pages = n.hosts.filter((h) => !own(h) && h.authenticated > 0);
  const background = n.hosts.filter((h) => !own(h) && h.authenticated === 0 && h.refusedUnauthenticated > 0);
  const forget = async () => {
    await api.clearNetworkRecords().catch(() => {});
    onChanged();
  };
  const p = n.proxy;
  return (
    <section className="card">
      <div className="page-head">
        <h2>DNS and network layer</h2>
        {p && <button className="btn" onClick={forget}>Forget records</button>}
      </div>
      {n.startError && <p className="notice danger">{n.startError}</p>}
      <dl className="facts-grid">
        <dt>Encrypted DNS</dt>
        <dd>
          {n.running[0].toUpperCase() + n.running.slice(1)}
          {n.configured !== n.running && ` now; ${n.configured} after you restart UNTRACE`}
        </dd>
        <dt>Names</dt><dd>{n.resolver}</dd>
        <dt>Start-up check</dt><dd>{checkText(n.check)}</dd>
        {p && (
          <>
            <dt>Proxy</dt>
            <dd className="mono">127.0.0.1:{p.port} · credentials required</dd>
            <dt>This session</dt>
            <dd>
              {p.connections} connection(s) for pages ({p.active} open) · {p.resolver.encrypted} encrypted and{" "}
              {p.resolver.windows} Windows lookup(s), {p.resolver.cached} answered from memory
              {p.resolver.fallbacks > 0 && `, ${p.resolver.fallbacks} encrypted lookup(s) failed and went to Windows`}
              {p.resolver.failed > 0 && `, ${p.resolver.failed} failed`}
            </dd>
            <dt>Refused</dt>
            <dd>
              {p.refusedUnauthenticated} without credentials (the engine's own background traffic, and each page
              session's first try) · {p.blockedThreats} malware/phishing · {p.blockedLocal} public name(s) pointing into
              your network · {p.malformed} malformed
            </dd>
          </>
        )}
      </dl>
      <h3 className="sub-head">This computer's DNS (read-only)</h3>
      {n.adapters.length === 0 && <p className="muted small">No active network adapter with DNS servers.</p>}
      {n.adapters.map((a) => (
        <div className="list-status" key={a.name}>
          <div className="row-title">
            {a.name} {a.hasGateway && <span className="tag">internet</span>}
          </div>
          <ul className="facts">
            {a.dnsServers.map((s) => (
              <li key={s.address}>
                <span className="mono">{s.address}</span>
                {" — "}
                {s.dohTemplate
                  ? `encrypted address known (${s.dohTemplateSource === "adapter_setting" ? "your Windows setting" : "Windows' list"}): ${s.dohTemplate}`
                  : "no known encrypted address"}
                {s.windowsEncryptionSet && "; Windows is set to encrypt lookups to it"}
              </li>
            ))}
          </ul>
        </div>
      ))}
      {(n.windowsPolicy.enableAutoDoh !== null || n.windowsPolicy.groupPolicy !== null) && (
        <p className="muted small">
          Windows policy values: EnableAutoDoh {n.windowsPolicy.enableAutoDoh ?? "not set"}, Group Policy DoH{" "}
          {n.windowsPolicy.groupPolicy ?? "not set"}.
        </p>
      )}
      {p && (
        <>
          <div className="page-head">
            <h3 className="sub-head">Hosts contacted this session ({pages.length})</h3>
            <button className="btn small-btn" onClick={() => setShowHosts((v) => !v)}>{showHosts ? "Hide" : "Show"}</button>
          </div>
          <p className="muted small">
            Kept in memory only and forgotten when UNTRACE closes. {background.length} host(s) were asked for without
            credentials and never by a page: the engine's own background traffic, refused (D-025)
            {background.length > 0 && `: ${background.map((h) => h.host).join(", ")}`}.
          </p>
          {showHosts && (
            <ul className="perm-list hosts">
              {pages.map((h) => (
                <li key={h.host}>
                  <span className="mono">{h.host}</span>
                  <span className={h.blockedThreat || h.blockedLocal || h.failed ? "danger small" : "muted small"}>
                    {h.blockedThreat
                      ? `blocked: ${h.threatList ?? "threat"}`
                      : h.blockedLocal
                        ? "refused: points into your network"
                        : h.failed && !h.connections
                          ? h.lastError ?? "failed"
                          : `${h.via ? VIA[h.via] ?? h.via : ""}${h.dnsServer ? ` · ${h.dnsServer}` : ""}${h.plainHttp ? " · plain HTTP" : ""}`}
                  </span>
                  <span className="muted small">{h.connections}×</span>
                </li>
              ))}
            </ul>
          )}
          {p.hostsNotListed > 0 && <p className="muted small">{p.hostsNotListed} more connection(s) not listed (limit reached).</p>}
        </>
      )}
    </section>
  );
}

/** M9 (D-016): UNTRACE's own updates: status, Check now, and Install (two steps). */
function AppUpdateRow() {
  const [s, setS] = useState<AppUpdateStatus | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);
  useEffect(() => {
    api.appUpdateStatus().then(setS).catch((e) => setNote(errorText(e)));
    const un = onAppUpdate(setS);
    return () => {
      un.then((f) => f());
    };
  }, []);
  if (!s) return <>—</>;
  if (!s.configured) {
    return <>Version {s.currentVersion}. This build has no release address or update key, so it does not check (a development or test build).</>;
  }
  const when = s.lastCheck ? new Date(s.lastCheck * 1000).toLocaleString() : null;
  const check = async () => {
    setNote(null);
    try {
      await api.appUpdateCheck();
    } catch (e) {
      setNote(errorText(e));
    }
  };
  const install = async () => {
    setNote(null);
    try {
      await api.appUpdateInstall(); // UNTRACE exits when the installer starts
    } catch (e) {
      setNote(errorText(e));
      setConfirm(false);
    }
  };
  return (
    <>
      Version {s.currentVersion}.{" "}
      {s.checking
        ? "Checking…"
        : s.installing
          ? "Downloading and checking the signature…"
          : when
            ? `Last checked ${when}: ${s.lastResult ?? "—"}.`
            : s.enabled
              ? "Not checked yet (UNTRACE checks once a day)."
              : "Automatic checks are off."}
      <div className="inline-form" style={{ marginTop: 6 }}>
        <button className="btn small-btn" disabled={s.checking || s.installing} onClick={check}>
          Check now
        </button>
        {s.available && !confirm && (
          <button className="btn small-btn primary" disabled={s.installing} onClick={() => setConfirm(true)}>
            Install UNTRACE {s.available.version}…
          </button>
        )}
      </div>
      {s.available && confirm && (
        <div style={{ marginTop: 8 }}>
          <p className="small">UNTRACE closes, installs the update and starts again. Settings and data are kept.</p>
          <div className="inline-form">
            <button className="btn small-btn primary" disabled={s.installing} onClick={install}>
              Install and restart
            </button>
            <button className="btn small-btn" disabled={s.installing} onClick={() => setConfirm(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
      {s.available?.notes && <p className="muted small">{s.available.notes}</p>}
      {note && <p className="small danger">{note}</p>}
    </>
  );
}

/** M7: run the self-check in a separate test window and show what it found, per protection. */
function SelfCheckSection() {
  const [last, setLast] = useState<SelfCheckLast | null>(null);
  const [titles, setTitles] = useState<Record<string, string>>({});
  const [note, setNote] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  const load = useCallback(() => {
    api.selfCheckLast().then(setLast).catch((e) => setNote(errorText(e)));
  }, []);
  useEffect(() => {
    load();
    api
      .settings()
      .then((s) => setTitles(Object.fromEntries(s.protections.map((p) => [p.id, p.title]))))
      .catch(() => {});
    const un = onSelfCheckDone((r) => {
      const notRun = r.skipped?.length ? ` ${r.skipped.length} not run: ${r.skipped.join("; ")}.` : "";
      setNote(
        r.ok
          ? r.passed
            ? notRun
              ? `Finished: no check failed.${notRun}`
              : "Finished: every check passed."
            : `Finished with failures: ${(r.failed ?? []).join("; ")}.${notRun}`
          : r.error ?? "The self-check failed.",
      );
      load();
    });
    return () => {
      un.then((f) => f());
    };
  }, [load]);

  const run = async () => {
    setNote(null);
    try {
      await api.selfCheckStart();
      load();
    } catch (e) {
      setNote(errorText(e));
    }
  };

  const failed = (last?.checks ?? []).filter((c) => !c.ok);
  const skipped = (last?.checks ?? []).filter((c) => c.skipped);
  return (
    <section className="card">
      <div className="page-head">
        <h2>Self-check</h2>
        <button className="btn" disabled={last?.running} onClick={run}>
          {last?.running ? "Running…" : "Run self-check"}
        </button>
      </div>
      <p className="muted small">
        A second UNTRACE opens in its own window with its own test data, offline, and exercises every protection end to
        end (about two minutes). Your tabs, settings and data are not touched. Please leave the test window alone until
        it closes.
      </p>
      {note && <p className="small" role="status">{note}</p>}
      {last?.running && <p className="small">The test window is open…</p>}
      {last && last.at && (
        <>
          <p className="small">
            Last run {last.at.slice(0, 16).replace("T", " ")} UTC: {last.checks.length - failed.length - skipped.length} of{" "}
            {last.checks.length} checks passed{skipped.length > 0 && `, ${skipped.length} not run`}
            {failed.length > 0 && `, ${failed.length} failed`}.
          </p>
          <ul className="facts">
            {(last.protections ?? []).map((p) => (
              <li key={p.id}>
                <span className={p.state === "passed" ? "" : p.state === "failed" ? "danger" : "muted"}>
                  {titles[p.id] ?? p.id}: {p.state === "not_run" ? "not run" : p.state === "partly" ? "partly run" : p.state}
                </span>
                {p.failed.length > 0 && <span className="danger small"> ({p.failed.join("; ")})</span>}
              </li>
            ))}
          </ul>
          {skipped.length > 0 && (
            <p className="muted small">
              Not run: {skipped.map((c) => c.name).join("; ")}. (The certificate check needs a test server that only the
              developer check script starts.)
            </p>
          )}
          <button className="btn small-btn" onClick={() => setOpen((v) => !v)}>
            {open ? "Hide all checks" : "Show all checks"}
          </button>
          {open && (
            <ul className="facts">
              {last.checks.map((c) => (
                <li key={c.name} className={c.ok ? "" : "danger"}>
                  {c.skipped ? "not run" : c.ok ? "passed" : "failed"} · {c.name}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
      {last && !last.at && !last.running && <p className="muted small">Not run yet on this computer.</p>}
    </section>
  );
}

export function DiagnosticsPage({ onOpenActivity }: { onOpenActivity: () => void }) {
  const [d, setD] = useState<Diagnostics | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setD(await api.diagnostics());
      setError(null);
    } catch (e) {
      setError(errorText(e));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const [reportNote, setReportNote] = useState<string | null>(null);
  const saveReport = async () => {
    setReportNote(null);
    try {
      const path = await api.reportSave();
      if (path) setReportNote(`Report saved to ${path}. It lists settings and checks only, never sites you visited.`);
    } catch (e) {
      setReportNote(errorText(e));
    }
  };

  const [updating, setUpdating] = useState(false);
  const [updateNote, setUpdateNote] = useState<string | null>(null);
  const updateNow = async () => {
    setUpdating(true);
    setUpdateNote(null);
    try {
      const changed = await api.updateListsNow();
      setUpdateNote(changed ? "New list versions were downloaded, checked and are now in use." : "Checked. See each list's last attempt below.");
    } catch (e) {
      setUpdateNote(errorText(e));
    }
    setUpdating(false);
    load();
  };

  if (error) return <div className="page"><div className="page-inner"><h1>Diagnostics</h1><p className="notice danger">{error}</p></div></div>;
  if (!d) return <div className="page"><div className="page-inner"><h1>Diagnostics</h1><p className="muted">Reading…</p></div></div>;
  const e = d.engine;

  return (
    <div className="page">
      <div className="page-inner">
        <div className="page-head">
          <h1>Diagnostics</h1>
          <div className="inline-form">
            <button className="btn" onClick={saveReport}>Save security report…</button>
            <button className="btn" onClick={load}>Refresh</button>
          </div>
        </div>
        {reportNote && <p className="small" role="status">{reportNote}</p>}

        <SelfCheckSection />

        <section className="card">
          <h2>Checks</h2>
          {d.checks.map((c) => (
            <div className="check" key={c.name}>
              <span className={`check-icon ${c.ok === true ? "pass" : c.ok === false ? "fail" : "unknown"}`} aria-label={c.ok === true ? "Passed" : c.ok === false ? "Failed" : "Not verified"}>
                {c.ok === true ? <Check /> : c.ok === false ? <Cross /> : <Question />}
              </span>
              <div>
                <div className="row-title">{c.name}</div>
                <div className="row-desc">{c.ok === null ? `Not verified yet. ${c.detail}` : c.detail}</div>
              </div>
            </div>
          ))}
        </section>

        <section className="card">
          <div className="page-head">
            <h2>Block lists</h2>
            <button className="btn" disabled={updating} onClick={updateNow}>
              {updating ? "Checking…" : "Check for new versions"}
            </button>
          </div>
          {updateNote && <p className="small">{updateNote}</p>}
          <p className="muted small">
            {d.filterBuildMs !== null
              ? `Filters last prepared in ${d.filterBuildMs} ms${d.filterBuildCached ? " from the verified cache" : " (built from the lists)"}.`
              : "Filters have not been prepared yet."}
          </p>
          {d.filterLists.map((l) => (
            <div className="list-status" key={l.id}>
              <div className="row-title">
                {l.title} <span className="tag">{l.enabled ? "on" : "off"}</span>
              </div>
              <dl className="facts-grid compact">
                <dt>Copy in use</dt>
                <dd>
                  {!l.enabled
                    ? "Not loaded"
                    : l.origin === "downloaded"
                      ? "Downloaded"
                      : l.origin === "previous"
                        ? "Previous download (the latest one was damaged)"
                        : "Shipped with UNTRACE"}
                  {l.version && <span className="mono"> · {l.version}</span>}
                  {l.rules !== null && ` · ${l.rules.toLocaleString()} rules`}
                </dd>
                <dt>Updates</dt>
                <dd>
                  Every {l.expiresHours >= 24 ? `${l.expiresHours / 24} days` : `${l.expiresHours} hours`}
                  {l.lastCheck ? ` · last checked ${l.lastCheck}` : " · not checked yet"}
                  {l.nextCheck && ` · next ${l.nextCheck}`}
                </dd>
                {l.lastError && (
                  <>
                    <dt>Last attempt</dt>
                    <dd className="danger">{l.lastError}</dd>
                  </>
                )}
                <dt>Source</dt><dd className="mono">{l.url}</dd>
                <dt>Licence</dt><dd>{l.licence}</dd>
              </dl>
            </div>
          ))}
        </section>

        <NetworkSection report={d.network} onChanged={load} />

        <section className="card">
          <h2>Browser engine</h2>
          {d.hostError && <p className="notice danger">{d.hostError}</p>}
          <dl className="facts-grid">
            <dt>WebView2 Runtime</dt><dd className="mono">{e?.runtimeVersion ?? "—"}</dd>
            <dt>Updates</dt><dd>Delivered automatically by Microsoft (Evergreen).</dd>
            <dt>Profile</dt><dd className="mono">{e?.profile ?? "—"}</dd>
            <dt>Tracking prevention</dt>
            <dd>
              {e
                ? `${e.trackingPreventionEnabled ? "Enabled" : "Disabled"} · level ${e.trackingPreventionLevel ?? "not reported"}` +
                  (e.tempTrackingPreventionLevel ? `, temporary tabs ${e.tempTrackingPreventionLevel}` : "") +
                  " (read back)"
                : "—"}
            </dd>
            <dt>Tracking parameters</dt><dd>{e ? (e.stripTrackingParams ? "Removed from page and frame addresses" : "Left in addresses") : "—"}</dd>
            <dt>Temporary tabs</dt><dd>{e?.temporaryTabs ?? 0} open</dd>
            <dt>Browser arguments</dt><dd className="mono">{e ? (e.browserArguments || "none") : "—"}</dd>
            <dt>Crash reports</dt><dd className="mono">{e?.crashReportFolder ?? "—"}</dd>
            <dt>Open tabs</dt><dd>{e?.openTabs ?? 0}</dd>
          </dl>
        </section>

        <section className="card">
          <h2>Updates</h2>
          <dl className="facts-grid">
            <dt>Browser engine</dt>
            <dd>
              WebView2 Runtime {e?.runtimeVersion ?? "—"}, updated automatically by Microsoft (Evergreen).
              {e?.updateAvailable ? " A newer version is installed and is used after you restart UNTRACE." : " No newer version is waiting."}
            </dd>
            <dt>Block lists</dt>
            <dd>
              {d.filterLists.filter((l) => l.enabled).map((l) => `${l.title}: ${l.lastCheck ? `checked ${l.lastCheck}` : "not checked yet"}`).join(" · ") || "No list is on."}
            </dd>
            <dt>UNTRACE itself</dt>
            <dd>
              <AppUpdateRow />
            </dd>
          </dl>
        </section>

        <section className="card">
          <h2>UNTRACE</h2>
          <dl className="facts-grid">
            <dt>Version</dt><dd className="mono">{d.appVersion} (Tauri {d.tauriVersion})</dd>
            <dt>Data folder</dt>
            <dd className="mono">{d.dataRoot}{d.dataRootOverridden && <span className="tag">development override</span>}</dd>
            <dt>Settings file</dt><dd className="mono">{d.settingsFile}</dd>
            <dt>Interface navigations refused</dt><dd>{d.uiNavigationBlocked}</dd>
            <dt>Clearing on exit</dt>
            <dd>{exitText(d)}</dd>
            <dt>Telemetry</dt><dd>None. UNTRACE sends no usage or error reports.</dd>
          </dl>
        </section>

        <section className="card">
          <div className="card-head">
            <h2>Audit log</h2>
            <div className="inline-form">
              <span className="muted small">{kb(d.auditBytes)} · never contains addresses</span>
              <button className="btn" onClick={onOpenActivity}>Open activity log</button>
              <button
                className="btn"
                onClick={async () => {
                  await api.clearAudit();
                  load();
                }}
              >
                Clear
              </button>
            </div>
          </div>
          <div className="audit">
            {[...d.auditTail].reverse().map((raw, i) => {
              const l = auditLine(raw);
              return (
                <div className="audit-line" key={i}>
                  <span className="audit-ts">{l.ts.replace("T", " ").replace("Z", "")}</span>
                  <span className="audit-ev">{l.event}</span>
                  <span className="audit-rest">{l.rest}</span>
                </div>
              );
            })}
          </div>
          <p className="muted small mono">{d.auditFile}</p>
        </section>
      </div>
    </div>
  );
}
