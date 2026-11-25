import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorText, onAppUpdate, onFocusAddress, onFocusPanel, onTabs, type SettingsView, type Snapshot } from "./api";
import { ContentSlot } from "./components/ContentSlot";
import { AboutPage } from "./components/AboutPage";
import { ActivityPage } from "./components/ActivityPage";
import { WelcomePage } from "./components/WelcomePage";
import { DataPage } from "./components/DataPage";
import { DiagnosticsPage } from "./components/DiagnosticsPage";
import { DownloadsPanel } from "./components/DownloadsPanel";
import { PromptBar } from "./components/PromptBar";
import { SettingsPage } from "./components/SettingsPage";
import { SitePanel } from "./components/SitePanel";
import { TabStrip } from "./components/TabStrip";
import { Toolbar, type Page, type Panel } from "./components/Toolbar";

const EMPTY: Snapshot = {
  tabs: [],
  active: null,
  runtimeVersion: null,
  engineError: null,
  engineUpdateAvailable: false,
  downloads: [],
  storedPermissions: [],
  siteExceptions: [],
  tempSiteExceptions: [],
  localNetworkSites: [],
  tempLocalNetworkSites: [],
};

export function App() {
  const [snap, setSnap] = useState<Snapshot>(EMPTY);
  const [settings, setSettings] = useState<SettingsView | null>(null);
  const [hostError, setHostError] = useState<string | null>(null);
  const [page, setPage] = useState<Page>("browse");
  // M9: a newer UNTRACE found by the daily check (shown, never installed by itself).
  const [updateVersion, setUpdateVersion] = useState<string | null>(null);
  useEffect(() => {
    api
      .appUpdateStatus()
      .then((s) => setUpdateVersion(s.available?.version ?? null))
      .catch(() => {});
    const un = onAppUpdate((s) => setUpdateVersion(s.available?.version ?? null));
    return () => {
      un.then((f) => f());
    };
  }, []);
  // M9: the welcome screen counts as seen once the user leaves it for anything but the
  // privacy notice it links to.
  const [welcomeOpen, setWelcomeOpen] = useState(false);
  useEffect(() => {
    if (page === "welcome") setWelcomeOpen(true);
    else if (welcomeOpen && page !== "about") {
      setWelcomeOpen(false);
      api.welcomeDone().catch(() => {});
    }
  }, [page, welcomeOpen]);
  const [panel, setPanel] = useState<Panel>(null);
  const addressRef = useRef<HTMLInputElement>(null);

  const focusAddress = useCallback(() => {
    setPage("browse");
    requestAnimationFrame(() => addressRef.current?.focus());
  }, []);

  useEffect(() => {
    const unTabs = onTabs(setSnap);
    const unFocus = onFocusAddress(focusAddress);
    const unPanel = onFocusPanel(() =>
      requestAnimationFrame(() => document.querySelector<HTMLButtonElement>(".interstitial .btn.primary")?.focus()),
    );
    api
      .uiReady()
      .then((b) => {
        setSnap(b.snapshot);
        setSettings(b.settings);
        setHostError(b.hostError);
        if (b.showWelcome) setPage("welcome");
        else focusAddress();
      })
      .catch((e) => setHostError(errorText(e)));
    return () => {
      unTabs.then((f) => f());
      unFocus.then((f) => f());
      unPanel.then((f) => f());
    };
  }, [focusAddress]);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = settings?.theme ?? "system";
    // D-053: a coloured accent sets these four; tokens.css falls back to the neutral look.
    const c = settings?.accents.find((a) => a.id === settings.accent)?.colors ?? null;
    const set = (name: string, value: string | undefined) =>
      value ? root.style.setProperty(name, value) : root.style.removeProperty(name);
    set("--accent-dark", c?.dark);
    set("--accent-dark-on", c?.darkOn);
    set("--accent-light", c?.light);
    set("--accent-light-on", c?.lightOn);
  }, [settings?.theme, settings?.accent, settings?.accents]);

  // Protection states are read back from the engine, so refresh them whenever Settings opens.
  useEffect(() => {
    if (page === "settings") api.settings().then(setSettings).catch(() => {});
  }, [page]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const k = e.key.toLowerCase();
      const ctrl = e.ctrlKey && !e.altKey;
      if ((ctrl && k === "l") || k === "f6" || (e.altKey && !e.ctrlKey && k === "d")) {
        e.preventDefault();
        focusAddress();
      } else if (ctrl && (k === "t" || k === "n") && !e.shiftKey) {
        e.preventDefault();
        api.tabNew().then(focusAddress);
      } else if (ctrl && e.shiftKey && k === "n") {
        e.preventDefault();
        api.tabNewTemporary().then(focusAddress);
      } else if (ctrl && k === "w") {
        e.preventDefault();
        if (snap.active !== null) api.tabClose(snap.active);
      } else if (e.ctrlKey && k === "tab") {
        e.preventDefault();
        api.tabCycle(!e.shiftKey);
      } else if (ctrl && k === ",") {
        e.preventDefault();
        setPage("settings");
      } else if (ctrl && k === "j") {
        e.preventDefault();
        setPage("browse");
        setPanel("downloads");
      } else if (k === "escape" && page !== "browse") {
        setPage("browse");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [snap.active, page, focusAddress]);

  const tab = snap.tabs.find((t) => t.id === snap.active);
  const engineError = hostError ?? snap.engineError;
  const configured = (id: string) => {
    const v = settings?.protections.find((p) => p.id === id)?.configured;
    return typeof v === "boolean" ? v : null;
  };
  const filtering = {
    ads: configured("filter.block_ads"),
    trackers: configured("filter.block_trackers"),
    malware: configured("filter.warn_malware"),
    phishing: configured("filter.warn_phishing"),
    hide: configured("filter.hide_elements"),
  };
  const trackingLevel = settings?.protections.find((p) => p.id === "privacy.tracking_prevention")?.configured;
  const dnsObserved = settings?.protections.find((p) => p.id === "network.encrypted_dns")?.observed;
  const privacy = {
    tracking: typeof trackingLevel === "string" ? trackingLevel : null,
    params: configured("privacy.strip_tracking_params"),
    localNetwork: configured("security.local_network"),
    dns: dnsObserved?.status === "verified" && typeof dnsObserved.detail === "string" ? dnsObserved.detail : null,
  };

  return (
    <div className="app">
      <TabStrip
        snap={snap}
        onNewTab={() => api.tabNew().then(focusAddress)}
        onNewTemporary={() => api.tabNewTemporary().then(focusAddress)}
      />
      <Toolbar
        tab={tab}
        page={page}
        panel={panel}
        downloads={snap.downloads}
        addressRef={addressRef}
        onPanel={setPanel}
        onPage={setPage}
        updateVersion={updateVersion}
      />
      <main className="main">
        {page === "browse" && (
          <div className={`browse${panel ? " with-panel" : ""}`}>
            <div className="page-column">
              {tab && <PromptBar tab={tab} />}
              <ContentSlot engineError={engineError} tab={tab} />
            </div>
            {panel === "site" && (
              <SitePanel
                tab={tab}
                stored={snap.storedPermissions}
                httpsOnly={configured("security.https_only")}
                filtering={filtering}
                privacy={privacy}
                exceptions={snap.siteExceptions}
                tempExceptions={snap.tempSiteExceptions}
                localSites={snap.localNetworkSites}
                tempLocalSites={snap.tempLocalNetworkSites}
                onClose={() => setPanel(null)}
              />
            )}
            {panel === "downloads" && <DownloadsPanel downloads={snap.downloads} onClose={() => setPanel(null)} />}
          </div>
        )}
        {page === "settings" && settings && (
          <SettingsPage
            settings={settings}
            onChange={setSettings}
            onOpenData={() => setPage("data")}
            onOpenAbout={() => setPage("about")}
          />
        )}
        {page === "diagnostics" && <DiagnosticsPage onOpenActivity={() => setPage("activity")} />}
        {page === "data" && <DataPage />}
        {page === "activity" && <ActivityPage onBack={() => setPage("diagnostics")} />}
        {page === "welcome" && (
          <WelcomePage
            onStart={() => {
              setPage("browse");
              focusAddress();
            }}
            onPrivacy={() => setPage("about")}
          />
        )}
        {page === "about" && <AboutPage onBack={() => setPage(welcomeOpen ? "welcome" : "settings")} />}
      </main>
    </div>
  );
}
