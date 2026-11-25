import { useEffect, useState } from "react";
import { api, errorText, type ConnectionInfo, type PageNetwork, type StoredPermission, type TabInfo } from "../api";
import { connectionOf, formatDate, hostOf, originOf, tabTitle } from "../util";
import { Close } from "./Icons";
import { Toggle } from "./Toggle";

/** Configured state of each list switch (null = unknown). */
export type Filtering = {
  ads: boolean | null;
  trackers: boolean | null;
  malware: boolean | null;
  phishing: boolean | null;
  /** M6: hide the space blocked ads leave. */
  hide: boolean | null;
};

/** Configured privacy controls (null = unknown). */
export type Privacy = {
  tracking: string | null;
  params: boolean | null;
  /** D-040 switch. */
  localNetwork: boolean | null;
  /** Encrypted DNS mode the engine runs with ("off" | "automatic" | "strict"), when verified. */
  dns: string | null;
};

// Only facts that are true in this version. Protections appear here as they ship.
const IN_EFFECT = [
  "Invalid certificates are always refused — there is no way to continue.",
  "Camera, microphone, location, notifications, clipboard and file access are asked about first. Requests mostly used for fingerprinting (installed fonts, motion sensors, MIDI…) are refused.",
  "Other applications open only after you confirm; link types known to be abused are refused.",
  "Downloads ask where to save, and files that can run code are flagged.",
  "Pop-ups that were not opened by a click are blocked.",
  "Passwords and form data are never saved.",
];

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

function blockedLines(t: TabInfo): string[] {
  const b = t.blocked;
  const out: string[] = [];
  if (b.requests) out.push(`${plural(b.requests, "ad or tracker request")} blocked`);
  if (b.threats) out.push(`${plural(b.threats, "request")} to malware or phishing sites blocked`);
  if (b.params) out.push(`${plural(b.params, "tracking parameter")} removed from addresses (${b.paramNames.join(", ")})`);
  if (b.localNetwork) out.push(`${plural(b.localNetwork, "request")} to this computer or your local network blocked`);
  if (b.permissions) out.push(`${plural(b.permissions, "permission request")} refused`);
  if (b.popups) out.push(`${plural(b.popups, "pop-up")} blocked`);
  if (b.externalApps) out.push(`${plural(b.externalApps, "attempt")} to open another application refused`);
  if (b.certificateErrors) out.push(`${plural(b.certificateErrors, "invalid certificate")} refused`);
  if (b.navigations) out.push(`${plural(b.navigations, "link")} to local files or internal pages blocked`);
  return out;
}

function filteringFacts(f: Filtering): string[] {
  const state = (v: boolean | null, on: string, off: string) => (v === null ? null : v ? on : off);
  return [
    state(f.ads, "Ad requests are blocked (EasyList).", "Ad blocking is off (change it in Settings)."),
    state(f.trackers, "Requests to known trackers are blocked (EasyPrivacy).", "Tracker blocking is off (change it in Settings)."),
    state(
      f.hide,
      "The space blocked ads leave is hidden (element-hiding rules of the same lists).",
      "Hiding the space blocked ads leave is off (change it in Settings).",
    ),
    state(
      f.malware,
      "Known malware sites are stopped with a warning first.",
      "Warnings about malware sites are off (change it in Settings).",
    ),
    state(
      f.phishing,
      "Known phishing sites are stopped with a warning first.",
      "Warnings about phishing sites are off (change it in Settings).",
    ),
  ].filter((x): x is string => x !== null);
}

/** Connection details exactly as the engine reports them for this page's origin. */
function ConnectionDetails({ info, origin }: { info: ConnectionInfo | null; origin: string }) {
  if (!info || info.origin !== origin) {
    return <p className="muted small">The engine has not reported connection details for this page yet.</p>;
  }
  const cipher = [info.protocol, info.keyExchange, info.cipher].filter(Boolean).join(" · ");
  return (
    <>
      {cipher && (
        <div className="kv">
          <span className="k">Protocol</span>
          <span className="v mono">{cipher}</span>
        </div>
      )}
      {info.subject && (
        <div className="kv">
          <span className="k">Certificate</span>
          <span className="v">
            Issued to <span className="mono">{info.subject}</span>
            {info.issuer && <> by <span className="mono">{info.issuer}</span></>}
            {info.validTo && <>, valid until {formatDate(info.validTo)}</>}
          </span>
        </div>
      )}
      {info.state !== "secure" && (
        <p className="small danger">
          The engine does not rate this page fully secure ({info.state}) — for example, parts of it may load without
          encryption.
        </p>
      )}
    </>
  );
}

/** Ads/trackers blocking for this page's site: saved in Settings, or for temporary tabs, kept
 * only until the temporary session ends. */
function SiteBlocking({
  site,
  exceptions,
  tempExceptions,
  temporary,
  filtering,
}: {
  site: string;
  exceptions: string[];
  tempExceptions: string[];
  temporary: boolean;
  filtering: Filtering;
}) {
  const [error, setError] = useState<string | null>(null);
  const saved = exceptions.includes(site);
  const on = !saved && !(temporary && tempExceptions.includes(site));
  const listsOff = filtering.ads === false && filtering.trackers === false;
  const set = (v: boolean) => {
    setError(null);
    // In a temporary tab the choice is never saved, unless it undoes a saved exception.
    api.setSiteFiltering(site, v, temporary && !saved).catch((e) => setError(errorText(e)));
  };
  return (
    <section className="panel-section">
      <div className="setting-row compact">
        <div>
          <h3>Block ads and trackers on {site}</h3>
          <p className="muted small">
            {on
              ? "Turn this off if the site does not work properly. Malware and phishing warnings stay on."
              : "Off for this site: its ads and trackers load and nothing is hidden. Malware and phishing warnings still apply."}
            {" Reload the page to see a change."}
            {temporary && !saved && " In temporary tabs this choice is forgotten when the last temporary tab closes."}
            {listsOff && " (Both lists are switched off in Settings, so nothing is blocked anywhere.)"}
          </p>
        </div>
        <Toggle checked={on} label={`Block ads and trackers on ${site}`} onChange={set} />
      </div>
      {error && <p className="small danger">{error}</p>}
    </section>
  );
}

/** How the network layer reached this page's host, as its record says. */
function dnsText(n: PageNetwork): string {
  if (!n.throughNetworkLayer) {
    return "Not seen by UNTRACE's network layer this session (the page may have come from the cache).";
  }
  switch (n.dns) {
    case "encrypted":
      return `Through UNTRACE's network layer; name looked up encrypted${n.dnsServer ? ` (${n.dnsServer})` : ""}.`;
    case "windows":
      return "Through UNTRACE's network layer; name looked up by Windows (encrypted only if Windows is set to encrypt).";
    case "literal":
      return "Through UNTRACE's network layer; an IP address, nothing to look up.";
    default:
      return "Through UNTRACE's network layer.";
  }
}

/** D-040: may this site's pages reach this computer and the local network? */
function SiteLocal({
  site,
  allowedSites,
  tempAllowedSites,
  temporary,
  blocked,
  protectionOn,
}: {
  site: string;
  allowedSites: string[];
  tempAllowedSites: string[];
  temporary: boolean;
  blocked: number;
  protectionOn: boolean | null;
}) {
  const [error, setError] = useState<string | null>(null);
  const saved = allowedSites.includes(site);
  const allowed = saved || (temporary && tempAllowedSites.includes(site));
  if (!allowed && blocked === 0) return null;
  const set = (v: boolean) => {
    setError(null);
    api.setSiteLocal(site, v, temporary && !saved).catch((e) => setError(errorText(e)));
  };
  return (
    <section className="panel-section">
      <div className="setting-row compact">
        <div>
          <h3>Let {site} reach your local network</h3>
          <p className="muted small">
            {allowed
              ? "Allowed: this site's pages can reach this computer and devices on your network. Turn it off unless the site is meant to control a device of yours."
              : `This page tried to reach this computer or a device on your network ${plural(blocked, "time")}. Allow it only for a site meant to control a device of yours, such as a router or smart-home app.`}
            {temporary && !saved && " In temporary tabs this choice is forgotten when the last temporary tab closes."}
            {protectionOn === false && " (The protection is switched off in Settings, so nothing is blocked anywhere.)"}
          </p>
        </div>
        <Toggle checked={allowed} label={`Let ${site} reach your local network`} onChange={set} />
      </div>
      {error && <p className="small danger">{error}</p>}
    </section>
  );
}

/** This site's cookies in normal tabs, read from the engine, with a delete button. */
function SiteData({ site, temporary }: { site: string; temporary: boolean }) {
  const [count, setCount] = useState<number | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (temporary) return;
    let live = true;
    setNote(null);
    api
      .cookieSites()
      .then((sites) => live && setCount(sites.find((s) => s.site === site)?.cookies ?? 0))
      .catch((e) => live && setNote(errorText(e)));
    return () => {
      live = false;
    };
  }, [site, temporary]);

  if (temporary) {
    return (
      <section className="panel-section">
        <h3>Cookies and site data</h3>
        <p className="muted small">
          This is a temporary tab: what {site} stores here is kept in memory and discarded when the last temporary tab
          closes. Normal tabs cannot see it.
        </p>
      </section>
    );
  }

  const remove = async () => {
    setBusy(true);
    setNote(null);
    try {
      const left = await api.deleteSiteData(site);
      setCount(left);
      setNote(
        left === 0
          ? "Deleted. The engine reports no cookies left for this site. Reload the page to start fresh."
          : `${plural(left, "cookie")} could not be deleted.`,
      );
    } catch (e) {
      setNote(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel-section">
      <div className="setting-row compact">
        <div>
          <h3>Cookies and site data</h3>
          <p className="muted small">
            {count === null
              ? "Reading cookies…"
              : count === 0
                ? `${site} has no cookies stored.`
                : `${site} has ${plural(count, "cookie")} stored. Deleting also removes its local storage, IndexedDB and service workers, and signs you out.`}
          </p>
        </div>
        <button className="btn small-btn" disabled={busy || count === null} onClick={remove}>
          {busy ? "Deleting…" : "Delete"}
        </button>
      </div>
      {note && <p className="small" role="status">{note}</p>}
    </section>
  );
}

type Props = {
  tab: TabInfo | undefined;
  stored: StoredPermission[];
  httpsOnly: boolean | null;
  filtering: Filtering;
  privacy: Privacy;
  exceptions: string[];
  tempExceptions: string[];
  localSites: string[];
  tempLocalSites: string[];
  onClose: () => void;
};

const TRACKING_TEXT: Record<string, string> = {
  off: "Tracking prevention is off (change it in Settings).",
  basic: "Tracking prevention is Basic: cryptomining and fingerprinting scripts are blocked.",
  balanced: "Tracking prevention is Balanced: known trackers cannot store cookies or data on sites you have not visited.",
  strict: "Tracking prevention is Strict: most known trackers are stopped from loading.",
};

const DNS_TEXT: Record<string, string> = {
  off: "Encrypted DNS is off: the engine looks names up itself, usually unencrypted (change it in Settings).",
  automatic: "Every request goes through UNTRACE's network layer; names are looked up encrypted when your DNS server offers it.",
  strict: "Every request goes through UNTRACE's network layer; every name is looked up encrypted with your chosen provider.",
};

export function SitePanel({ tab, stored, httpsOnly, filtering, privacy, exceptions, tempExceptions, localSites, tempLocalSites, onClose }: Props) {
  const url = tab?.url ?? "";
  const conn = connectionOf(url);
  const host = hostOf(url);
  const origin = originOf(url);
  const saved = origin ? stored.filter((s) => s.origin === origin) : [];
  const blocked = tab ? blockedLines(tab) : [];
  const hosts = [...(tab?.blocked.hosts ?? [])].sort((a, b) => b.count - a.count);
  const site = tab?.site && (conn === "https" || conn === "http") ? tab.site : null;
  const temporary = tab?.temporary ?? false;

  return (
    <aside className="side-panel" aria-label="About this page">
      <header className="panel-head">
        <h2>About this page</h2>
        <button className="icon-btn" aria-label="Close panel" onClick={onClose}>
          <Close />
        </button>
      </header>

      <section className="panel-section">
        <div className="kv">
          <span className="k">Page</span>
          <span className="v">{tab ? tabTitle(tab) : "—"}</span>
        </div>
        <div className="kv">
          <span className="k">Site</span>
          <span className="v mono">{host || "—"}</span>
        </div>
        <div className="kv">
          <span className="k">Connection</span>
          <span className={`v${conn === "http" ? " danger" : ""}`}>
            {conn === "https" && "Encrypted (HTTPS)"}
            {conn === "http" && "Not encrypted (HTTP) — others on the network can read and change this page"}
            {conn === "none" && "No page loaded"}
            {conn === "other" && "Local or internal page"}
          </span>
        </div>
        {conn === "https" && <ConnectionDetails info={tab?.connection ?? null} origin={origin} />}
        {tab?.network && (conn === "https" || conn === "http") && (
          <div className="kv">
            <span className="k">Route</span>
            <span className="v">{dnsText(tab.network)}</span>
          </div>
        )}
        {temporary && (
          <p className="small temp-note">
            Temporary tab. Cookies, storage, cache and history of temporary tabs are discarded when the last one closes.
          </p>
        )}
      </section>

      {site && (
        <SiteBlocking
          site={site}
          exceptions={exceptions}
          tempExceptions={tempExceptions}
          temporary={temporary}
          filtering={filtering}
        />
      )}
      {site && (
        <SiteLocal
          site={site}
          allowedSites={localSites}
          tempAllowedSites={tempLocalSites}
          temporary={temporary}
          blocked={tab?.blocked.localNetwork ?? 0}
          protectionOn={privacy.localNetwork}
        />
      )}
      {site && <SiteData site={site} temporary={temporary} />}

      <section className="panel-section">
        <h3>Refused on this page</h3>
        {blocked.length === 0 ? (
          <p className="muted small">Nothing so far.</p>
        ) : (
          <ul className="facts">{blocked.map((b) => <li key={b}>{b}</li>)}</ul>
        )}
        {hosts.length > 0 && (
          <ul className="perm-list hosts">
            {hosts.slice(0, 12).map((h) => (
              <li key={h.host}>
                <span className="mono">{h.host}</span>
                <span className={h.threat ? "danger small" : "muted small"}>
                  {h.threat === "malware" ? "malware" : h.threat === "phishing" ? "phishing" : h.local ? "local network" : ""}
                </span>
                <span className="muted small">{h.count}×</span>
              </li>
            ))}
          </ul>
        )}
        {hosts.length > 12 && <p className="muted small">and {plural(hosts.length - 12, "more site")}.</p>}
      </section>

      {origin && (
        <section className="panel-section">
          <h3>Saved permissions for this site</h3>
          {saved.length === 0 ? (
            <p className="muted small">None. Decisions are only saved when you tick “Remember for this site”.</p>
          ) : (
            <ul className="perm-list">
              {saved.map((s) => (
                <li key={`${s.permission}`}>
                  <span>{s.label}</span>
                  <span className={s.state === "allow" ? "" : "muted"}>{s.state === "allow" ? "Allowed" : "Blocked"}</span>
                  <button className="btn small-btn" onClick={() => api.resetPermission(s.origin, s.permission).catch(() => {})}>
                    Reset
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      <section className="panel-section">
        <h3>In effect on every page</h3>
        <ul className="facts">
          <li>
            HTTPS-only mode is {httpsOnly === null ? "…" : httpsOnly ? "on: pages load over encrypted connections" : "off (change it in Settings)"}.
          </li>
          {filteringFacts(filtering).map((f) => (
            <li key={f}>{f}</li>
          ))}
          {privacy.tracking && TRACKING_TEXT[privacy.tracking] && <li>{TRACKING_TEXT[privacy.tracking]}</li>}
          {privacy.dns && DNS_TEXT[privacy.dns] && <li>{DNS_TEXT[privacy.dns]}</li>}
          {privacy.localNetwork !== null && (
            <li>
              {privacy.localNetwork
                ? "Parts of public sites cannot reach this computer or devices on your network."
                : "Public sites can reach this computer and devices on your network (change it in Settings)."}
            </li>
          )}
          {privacy.params !== null && (
            <li>
              {privacy.params
                ? "Tracking parameters (utm_source, gclid, fbclid…) are removed from addresses before they are sent."
                : "Tracking parameters are left in addresses (change it in Settings)."}
            </li>
          )}
          {IN_EFFECT.map((f) => (
            <li key={f}>{f}</li>
          ))}
        </ul>
        <p className="muted small">UNTRACE only shows a protection once it can enforce and verify it.</p>
      </section>
    </aside>
  );
}
