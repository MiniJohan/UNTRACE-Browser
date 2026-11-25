import { useState, type CSSProperties } from "react";
import { Toggle } from "./Toggle";
import {
  api,
  errorText,
  type Accent,
  type ChangeOutcome,
  type PageColorScheme,
  type ProtectionStatus,
  type ProtectionValue,
  type SearchEngine,
  type SelfTestResult,
  type SettingsView,
  type Theme,
} from "../api";

const fmt = (v: ProtectionValue) => (v === true ? "On" : v === false ? "Off" : String(v)[0].toUpperCase() + String(v).slice(1));

function stateLine(p: ProtectionStatus): { text: string; verified: boolean } {
  if (p.observed.status === "verified" && p.observed.detail !== p.configured && p.scope === "environment") {
    return { text: `${fmt(p.observed.detail)} now · verified. ${fmt(p.configured)} after you restart UNTRACE.`, verified: true };
  }
  if (p.observed.status === "verified") {
    return { text: `${fmt(p.observed.detail)} · verified`, verified: true };
  }
  return { text: `${fmt(p.configured)} · not verified — ${p.observed.detail}`, verified: false };
}

function selfTestText(t: SelfTestResult | undefined): string {
  const when = t?.at ? ` · ${t.at.slice(0, 16).replace("T", " ")} UTC` : "";
  switch (t?.state) {
    case "passed":
      return `Self-test passed${when}.`;
    case "failed":
      return `Self-test failed${when}: ${t.failed.join("; ")}.`;
    case "partly":
      return `Self-test partly run${when} (some of its checks were skipped).`;
    default:
      return "Self-test not run yet (Diagnostics › Run self-check).";
  }
}

/** D-053: what pages should be told, from the saved choice. */
function expectedScheme(s: SettingsView): PageColorScheme {
  if (!s.pagesFollowTheme || s.theme === "system") return "auto";
  return s.theme === "light" ? "light" : "dark";
}

function pagesSchemeVerified(s: SettingsView): boolean {
  return !s.pagesSchemeError && s.pagesScheme === expectedScheme(s);
}

function pagesSchemeText(s: SettingsView): string {
  if (s.pagesSchemeError) return `Not verified: ${s.pagesSchemeError}`;
  if (!s.pagesScheme) return "Applied when the first tab starts.";
  const said = s.pagesScheme === "auto" ? "follow Windows" : s.pagesScheme;
  return s.pagesScheme === expectedScheme(s)
    ? `Websites are told: ${said} · verified`
    : `Not verified: the engine reports "${said}"`;
}

function outcomeText(o: ChangeOutcome): string {
  switch (o.outcome) {
    case "verified":
      return "Saved and verified.";
    case "unverified":
      return `Saved, but it could not be verified: ${o.reason}`;
    case "pending_restart":
      return "Saved. Takes effect after you restart UNTRACE.";
    case "reverted":
      return `Not changed: ${o.reason} Your previous setting is still in effect.`;
    case "rejected":
      return `Not changed: ${o.reason}`;
  }
}


type Props = { settings: SettingsView; onChange: (s: SettingsView) => void; onOpenData: () => void; onOpenAbout: () => void };

export function SettingsPage({ settings, onChange, onOpenData, onOpenAbout }: Props) {
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [template, setTemplate] = useState(settings.customTemplate ?? "");
  const [searchError, setSearchError] = useState<string | null>(null);
  const [dohTemplate, setDohTemplate] = useState(settings.customDoh?.template ?? "");
  const [dohAddress, setDohAddress] = useState(settings.customDoh?.address ?? "");
  const [dohNote, setDohNote] = useState<string | null>(null);

  const saveDoh = async () => {
    setDohNote(null);
    try {
      onChange(await api.setCustomDoh(dohTemplate, dohAddress));
      setDohNote("Saved.");
    } catch (e) {
      setDohNote(errorText(e));
    }
  };
  const groups = [...new Set(settings.protections.map((p) => p.group))];

  const setProtection = async (p: ProtectionStatus, value: ProtectionValue) => {
    try {
      const o = await api.setProtection(p.id, value);
      setNotes((n) => ({ ...n, [p.id]: outcomeText(o) }));
    } catch (e) {
      setNotes((n) => ({ ...n, [p.id]: errorText(e) }));
    }
    onChange(await api.settings());
  };

  const [appearanceError, setAppearanceError] = useState<string | null>(null);
  const appearance = async (f: () => Promise<SettingsView>) => {
    setAppearanceError(null);
    try {
      onChange(await f());
    } catch (e) {
      setAppearanceError(errorText(e));
      onChange(await api.settings());
    }
  };
  const setTheme = (t: Theme) => appearance(() => api.setTheme(t));
  const setAccent = (a: Accent) => appearance(() => api.setAccent(a));
  const setPagesFollow = (on: boolean) => appearance(() => api.setPagesFollowTheme(on));

  const setEngine = async (engine: SearchEngine) => {
    setSearchError(null);
    if (engine === "custom" && !template) {
      onChange({ ...settings, searchEngine: "custom" });
      return;
    }
    try {
      onChange(await api.setSearch(engine, engine === "custom" ? template : null));
    } catch (e) {
      setSearchError(errorText(e));
    }
  };

  return (
    <div className="page">
      <div className="page-inner">
        <h1>Settings</h1>

        {settings.configStatus.kind === "reset" && (
          <p className="notice danger">
            Your settings file could not be used ({settings.configStatus.reason}) and was replaced with defaults.
            {settings.configStatus.backup && <> The old file was kept at <span className="mono">{settings.configStatus.backup}</span>.</>}
          </p>
        )}
        {settings.configStatus.kind === "repaired" && (
          <p className="notice">Some settings were invalid and were repaired: {settings.configStatus.repairs.join("; ")}</p>
        )}

        <section className="card">
          <h2>Appearance</h2>
          <div className="row">
            <div className="row-text">
              <div className="row-title">Theme</div>
              <div className="row-desc">System follows Windows. Black uses true black, which suits OLED screens.</div>
            </div>
            <div className="segmented" role="radiogroup" aria-label="Theme">
              {(["system", "light", "dark", "black"] as Theme[]).map((t) => (
                <button key={t} role="radio" aria-checked={settings.theme === t} className={settings.theme === t ? "on" : ""} onClick={() => setTheme(t)}>
                  {t[0].toUpperCase() + t.slice(1)}
                </button>
              ))}
            </div>
          </div>
          <div className="row">
            <div className="row-text">
              <div className="row-title">Accent colour</div>
              <div className="row-desc">Colours the active tab, switches, buttons and the focus outline. Only UNTRACE's own window uses it; websites never see it.</div>
            </div>
            <div className="swatches" role="radiogroup" aria-label="Accent colour">
              {settings.accents.map((a) => (
                <button
                  key={a.id}
                  role="radio"
                  aria-checked={settings.accent === a.id}
                  aria-label={a.label}
                  title={a.label}
                  className={`swatch${settings.accent === a.id ? " on" : ""}`}
                  style={
                    a.colors
                      ? ({ "--swatch-dark": a.colors.dark, "--swatch-light": a.colors.light } as CSSProperties)
                      : undefined
                  }
                  onClick={() => setAccent(a.id)}
                />
              ))}
            </div>
          </div>
          <div className="row">
            <div className="row-text">
              <div className="row-title">Websites follow this theme</div>
              <div className="row-desc">
                Sites that have a dark mode use it while UNTRACE is Dark or Black, and their light look while it is Light. With
                System, or with this off, they follow Windows.
              </div>
              <div className={`row-state${pagesSchemeVerified(settings) ? "" : " unverified"}`}>{pagesSchemeText(settings)}</div>
              <div className="row-limits">
                Sites without a dark mode are not changed. Sites can read this preference, as they can in every browser.
              </div>
            </div>
            <Toggle checked={settings.pagesFollowTheme} label="Websites follow this theme" onChange={setPagesFollow} />
          </div>
          {appearanceError && <p className="small danger" role="status">{appearanceError}</p>}
        </section>

        <section className="card">
          <h2>Search</h2>
          <div className="row">
            <div className="row-text">
              <div className="row-title">Search engine</div>
              <div className="row-desc">Used when what you type is not a web address. UNTRACE never sends what you type before you press Enter.</div>
            </div>
            <select className="select" value={settings.searchEngine} onChange={(e) => setEngine(e.target.value as SearchEngine)} aria-label="Search engine">
              {settings.engines.map((e) => (
                <option key={e.id} value={e.id}>
                  {e.label}
                </option>
              ))}
            </select>
          </div>
          {settings.searchEngine === "custom" && (
            <div className="row">
              <div className="row-text">
                <div className="row-title">Custom search address</div>
                <div className="row-desc">An https:// address with <span className="mono">{"{q}"}</span> where the search terms go.</div>
              </div>
              <div className="inline-form">
                <input className="text-input mono" value={template} placeholder="https://search.example/?q={q}" onChange={(e) => setTemplate(e.target.value)} aria-label="Custom search address" />
                <button className="btn" onClick={() => setEngine("custom")}>Save</button>
              </div>
            </div>
          )}
          {searchError && <p className="note danger">{searchError}</p>}
        </section>

        {groups.map((g) => (
          <section className="card" key={g}>
            <h2>{g}</h2>
            {settings.protections
              .filter((p) => p.group === g)
              .map((p) => {
                const st = stateLine(p);
                return (
                  <div className="row" key={p.id}>
                    <div className="row-text">
                      <div className="row-title">{p.title}</div>
                      <div className="row-desc">{p.explanation}</div>
                      <div className={`row-state${st.verified ? "" : " unverified"}`}>{st.text}</div>
                      <div className="row-limits">{selfTestText(settings.selfTests[p.id])}</div>
                      {p.limitations && <div className="row-limits">{p.limitations}</div>}
                      {notes[p.id] && <div className="note" role="status">{notes[p.id]}</div>}
                      {p.id === "network.doh_provider" && p.configured === "custom" && (
                        <div className="sub-form">
                          <div className="row-desc">
                            Your server's DNS-over-HTTPS address and its IP address (Windows connects to the IP address
                            and does not look the name up).
                          </div>
                          <div className="inline-form">
                            <input className="text-input mono" value={dohTemplate} placeholder="https://dns.example/dns-query" onChange={(e) => setDohTemplate(e.target.value)} aria-label="DNS-over-HTTPS address" />
                            <input className="text-input mono short" value={dohAddress} placeholder="IP address" onChange={(e) => setDohAddress(e.target.value)} aria-label="Server IP address" />
                            <button className="btn" onClick={saveDoh}>Save</button>
                          </div>
                          {dohNote && <div className="note" role="status">{dohNote}</div>}
                        </div>
                      )}
                    </div>
                    {p.kind.type === "toggle" ? (
                      <Toggle checked={p.configured === true} label={p.title} onChange={(v) => setProtection(p, v)} />
                    ) : (
                      <select className="select" value={String(p.configured)} onChange={(e) => setProtection(p, e.target.value)} aria-label={p.title}>
                        {p.kind.options.map((o) => (
                          <option key={o} value={o}>{fmt(o)}</option>
                        ))}
                      </select>
                    )}
                  </div>
                );
              })}
          </section>
        ))}

        <section className="card">
          <h2>Your data</h2>
          <div className="row">
            <div className="row-text">
              <div className="row-title">What is stored, and where</div>
              <div className="row-desc">
                Cookies by site, cache, saved permissions, crash reports and everything else UNTRACE and its engine keep,
                with sizes, how long each is kept, and buttons to delete it now.
              </div>
            </div>
            <button className="btn" onClick={onOpenData}>Open</button>
          </div>
        </section>

        <section className="card">
          <h2>About</h2>
          <div className="row">
            <div className="row-text">
              <div className="row-title">About UNTRACE</div>
              <div className="row-desc">Version, licence, the privacy notice and the licences of the software UNTRACE is built with.</div>
            </div>
            <button className="btn" onClick={onOpenAbout}>Open</button>
          </div>
        </section>

      </div>
    </div>
  );
}
