// Typed bridge to UNTRACE's Rust commands. Every argument is validated again in Rust.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type ListId = "easy_list" | "easy_privacy" | "malware" | "phishing";

export type BlockedHost = { host: string; count: number; threat: ListId | null; local: boolean };

export type Blocked = {
  permissions: number;
  popups: number;
  externalApps: number;
  certificateErrors: number;
  navigations: number;
  /** Requests blocked by the ads/trackers lists. */
  requests: number;
  /** Requests to malware/phishing hosts blocked inside the page. */
  threats: number;
  hosts: BlockedHost[];
  /** Tracking parameters removed from this page's and its frames' addresses. */
  params: number;
  paramNames: string[];
  /** Requests from this public page to this computer or the local network, blocked. */
  localNetwork: number;
};

/** How the network layer reached a page's host (read from the proxy's record). */
export type DnsVia = "literal" | "encrypted" | "windows" | "test";
export type PageNetwork = { throughNetworkLayer: boolean; dns: DnsVia | null; dnsServer: string | null };

export type NetworkCheck =
  | { state: "off" }
  | { state: "not_run" }
  | { state: "pending" }
  | { state: "passed"; ms: number }
  | { state: "failed"; reason: string };

export type CertInfo = { subject: string; issuer: string; validFrom: number | null; validTo: number | null };

export type Interstitial =
  | { kind: "https_unavailable"; url: string; http_url: string; host: string; reason: string }
  | { kind: "certificate"; url: string; host: string; reason: string; certificate: CertInfo | null }
  | { kind: "load_error"; url: string; host: string; reason: string }
  | { kind: "threat"; url: string; host: string; list: ListId; list_title: string; list_homepage: string };

export type PermissionName =
  | "microphone" | "camera" | "geolocation" | "notifications" | "other_sensors" | "clipboard_read"
  | "multiple_automatic_downloads" | "file_read_write" | "autoplay" | "local_fonts" | "midi_sysex"
  | "window_management" | "unknown";

export type PromptDetail =
  | { type: "permission"; permission: PermissionName; label: string; phrase: string }
  | { type: "external_app"; scheme: string; target: string }
  | { type: "download"; file_name: string; size: number | null; risk: "normal" | "runs_code" };

export type PromptInfo = { id: number; origin: string; detail: PromptDetail };

export type TabInfo = {
  id: number;
  title: string;
  url: string;
  loading: boolean;
  canGoBack: boolean;
  canGoForward: boolean;
  favicon: string | null;
  crashed: boolean;
  ready: boolean;
  lastError: string | null;
  httpStatus: number | null;
  blocked: Blocked;
  interstitial: Interstitial | null;
  prompts: PromptInfo[];
  notice: string | null;
  connection: ConnectionInfo | null;
  /** The page's site (registrable domain), for per-site settings. */
  site: string | null;
  /** Temporary tab: nothing is kept after the last temporary tab closes. */
  temporary: boolean;
  network: PageNetwork | null;
};

/** The engine's own security verdict for a page (read back, not assumed). */
export type ConnectionInfo = {
  origin: string;
  state: "secure" | "neutral" | "insecure" | "insecure-broken" | "info" | "unknown" | string;
  protocol: string | null;
  keyExchange: string | null;
  cipher: string | null;
  subject: string | null;
  issuer: string | null;
  validFrom: number | null;
  validTo: number | null;
};

export type DownloadInfo = {
  id: number;
  fileName: string;
  path: string;
  state: "in_progress" | "completed" | "interrupted";
  received: number;
  total: number | null;
  risk: "normal" | "runs_code";
};

export type StoredPermission = { origin: string; permission: PermissionName; label: string; state: "allow" | "deny" };

export type Snapshot = {
  tabs: TabInfo[];
  active: number | null;
  runtimeVersion: string | null;
  engineError: string | null;
  engineUpdateAvailable: boolean;
  downloads: DownloadInfo[];
  storedPermissions: StoredPermission[];
  /** Sites where ads/trackers blocking is off. */
  siteExceptions: string[];
  /** The same, made in temporary tabs (this temporary session only). */
  tempSiteExceptions: string[];
  /** Sites allowed to reach this computer and the local network. */
  localNetworkSites: string[];
  tempLocalNetworkSites: string[];
};

export type CookieSite = { site: string; cookies: number; hosts: string[] };

export type DataItem = {
  id: string;
  title: string;
  what: string;
  location: string | null;
  bytes: number | null;
  retention: string;
  /** Label of the button that deletes it now. */
  action: string | null;
};

export type ExitKinds = { cache: boolean; siteData: boolean };

export type ExitRecord = {
  state: "pending" | "done" | "failed" | "timed_out" | string;
  kinds: ExitKinds;
  at: number;
  cookiesLeft: number | null;
  detail: string | null;
};

export type ListStatus = {
  id: ListId;
  protection: string;
  title: string;
  kind: "content" | "threat";
  enabled: boolean;
  origin: "bundled" | "downloaded" | "previous" | null;
  version: string | null;
  rules: number | null;
  expiresHours: number;
  lastCheck: string | null;
  nextCheck: string | null;
  lastError: string | null;
  homepage: string;
  licence: string;
  url: string;
};

export type ProtectionValue = boolean | string;

export type Observed =
  | { status: "verified"; detail: ProtectionValue }
  | { status: "unverifiable"; detail: string };

export type ProtectionStatus = {
  id: string;
  group: string;
  title: string;
  explanation: string;
  limitations: string;
  scope: "app" | "environment" | "profile" | "view";
  kind: { type: "toggle"; default: boolean } | { type: "choice"; options: string[]; default: string };
  configured: ProtectionValue;
  observed: Observed;
};

export type ChangeOutcome =
  | { outcome: "verified" }
  | { outcome: "unverified"; reason: string }
  | { outcome: "pending_restart" }
  | { outcome: "reverted"; reason: string }
  | { outcome: "rejected"; reason: string };

export type Theme = "system" | "dark" | "black" | "light";
/** D-053: accent presets; Grey keeps the neutral look. */
export type Accent = "grey" | "blue" | "teal" | "green" | "amber" | "rose" | "violet";
export type AccentOption = {
  id: Accent;
  label: string;
  /** Null for Grey. `dark` is used on the dark and black themes, `light` on the light theme. */
  colors: { dark: string; darkOn: string; light: string; lightOn: string } | null;
};
export type PageColorScheme = "auto" | "light" | "dark";
export type SearchEngine = "duck-duck-go" | "startpage" | "brave-search" | "mojeek" | "custom";

export type LoadOutcome =
  | { kind: "created" }
  | { kind: "loaded" }
  | { kind: "repaired"; repairs: string[] }
  | { kind: "reset"; reason: string; backup: string | null };

export type SettingsView = {
  theme: Theme;
  accent: Accent;
  accents: AccentOption[];
  pagesFollowTheme: boolean;
  /** Read back from the engine; null before a tab has started. */
  pagesScheme: PageColorScheme | null;
  pagesSchemeError: string | null;
  searchEngine: SearchEngine;
  customTemplate: string | null;
  customDoh: { template: string; address: string } | null;
  /** The last self-check's result per protection (M7). */
  selfTests: Record<string, SelfTestResult>;
  engines: { id: SearchEngine; label: string }[];
  protections: ProtectionStatus[];
  configStatus: LoadOutcome;
};

export type SelfTestResult = {
  state: "passed" | "failed" | "partly" | "not_run";
  at: string | null;
  failed: string[];
};

export type SelfCheckLast = {
  running: boolean;
  at: string | null;
  passed: boolean | null;
  checks: { name: string; ok: boolean; skipped: boolean }[];
  protections: { id: string; state: SelfTestResult["state"]; failed: string[]; checks: string[] }[] | null;
};

export type Bootstrap = { snapshot: Snapshot; settings: SettingsView; hostError: string | null; showWelcome: boolean };

/** M9 (D-016): UNTRACE's own updates. */
export type AppUpdateStatus = {
  currentVersion: string;
  configured: boolean;
  enabled: boolean;
  checking: boolean;
  installing: boolean;
  /** Seconds since 1970. */
  lastCheck: number | null;
  lastResult: string | null;
  available: { version: string; notes: string | null; date: string | null } | null;
};

/** M9: the About page. */
export type About = {
  version: string;
  runtimeVersion: string | null;
  licence: string;
  licenceText: string;
  privacy: string;
};

export type EngineInfo = {
  runtimeVersion: string | null;
  engineError: string | null;
  profile: string;
  dataDir: string;
  trackingPreventionEnabled: boolean;
  trackingPreventionLevel: string | null;
  tempTrackingPreventionLevel: string | null;
  temporaryTabs: number;
  stripTrackingParams: boolean;
  crashReportsLocal: boolean;
  crashReportFolder: string | null;
  browserArguments: string;
  openTabs: number;
  updateAvailable: boolean;
  networkLayer: boolean;
  hideElements: boolean;
  hideElementsTabs: number;
  hideElementsScriptBytes: number;
  networkCheck: NetworkCheck | null;
  localNetworkProtection: boolean;
  localNetworkWorkerBlocked: number;
};

export type HostRecord = {
  host: string;
  connections: number;
  /** Requests that carried this launch's credentials. */
  authenticated: number;
  /** Plain-HTTP requests among them (the rest are encrypted tunnels). */
  plainHttp: number;
  refusedUnauthenticated: number;
  blockedThreat: number;
  threatList: ListId | null;
  blockedLocal: number;
  failed: number;
  via: DnsVia | null;
  dnsServer: string | null;
  lastError: string | null;
};

export type ProxyStats = {
  port: number;
  connections: number;
  active: number;
  refusedUnauthenticated: number;
  blockedThreats: number;
  blockedLocal: number;
  failed: number;
  malformed: number;
  hostsNotListed: number;
  resolver: { encrypted: number; windows: number; cached: number; failed: number; fallbacks: number };
  dnsCacheEntries: number;
};

export type DnsServerInfo = {
  address: string;
  dohTemplate: string | null;
  dohTemplateSource: "windows_list" | "adapter_setting" | null;
  windowsEncryptionSet: boolean;
};

export type NetworkReport = {
  configured: string;
  running: string;
  startError: string | null;
  check: NetworkCheck | null;
  proxy: ProxyStats | null;
  resolver: string;
  adapters: { name: string; hasGateway: boolean; dnsServers: DnsServerInfo[] }[];
  windowsPolicy: { enableAutoDoh: number | null; groupPolicy: number | null };
  hosts: HostRecord[];
};

export type Check = { name: string; ok: boolean | null; detail: string };

export type Diagnostics = {
  appVersion: string;
  tauriVersion: string;
  engine: EngineInfo | null;
  hostError: string | null;
  dataRoot: string;
  dataRootOverridden: boolean;
  settingsFile: string;
  configStatus: LoadOutcome;
  auditFile: string;
  auditBytes: number;
  auditTail: string[];
  uiNavigationBlocked: number;
  checks: Check[];
  filterLists: ListStatus[];
  filterBuildMs: number | null;
  filterBuildCached: boolean | null;
  lastExitClear: ExitRecord | null;
  startClear: ExitKinds | null;
  network: NetworkReport;
};

export type Bounds = { x: number; y: number; width: number; height: number; visible: boolean };

export const api = {
  uiReady: () => invoke<Bootstrap>("ui_ready"),
  welcomeDone: () => invoke<void>("welcome_done"),
  about: () => invoke<About>("about_get"),
  notices: () => invoke<string>("notices_get"),
  appUpdateStatus: () => invoke<AppUpdateStatus>("app_update_status"),
  appUpdateCheck: () => invoke<AppUpdateStatus["available"]>("app_update_check"),
  /** Downloads, verifies and starts the installer; UNTRACE then exits. */
  appUpdateInstall: () => invoke<void>("app_update_install"),
  tabNew: () => invoke<number>("tab_new"),
  tabNewTemporary: () => invoke<number>("tab_new_temporary"),
  tabClose: (id: number) => invoke<void>("tab_close", { id }),
  tabActivate: (id: number) => invoke<void>("tab_activate", { id }),
  tabCycle: (forward: boolean) => invoke<void>("tab_cycle", { forward }),
  navigate: (input: string) => invoke<void>("navigate", { input }),
  back: () => invoke<void>("go_back"),
  forward: () => invoke<void>("go_forward"),
  reload: () => invoke<void>("reload"),
  stop: () => invoke<void>("stop"),
  setContentBounds: (b: Bounds) => invoke<void>("set_content_bounds", b),
  focusContent: () => invoke<void>("focus_content"),
  settings: () => invoke<SettingsView>("settings_get"),
  setProtection: (id: string, value: ProtectionValue) => invoke<ChangeOutcome>("protection_set", { id, value }),
  setTheme: (theme: Theme) => invoke<SettingsView>("theme_set", { theme }),
  setAccent: (accent: Accent) => invoke<SettingsView>("accent_set", { accent }),
  setPagesFollowTheme: (on: boolean) => invoke<SettingsView>("pages_theme_set", { on }),
  setSearch: (engine: SearchEngine, customTemplate: string | null) =>
    invoke<SettingsView>("search_set", { engine, customTemplate }),
  diagnostics: () => invoke<Diagnostics>("diagnostics_get"),
  clearAudit: () => invoke<void>("audit_clear"),
  interstitialAction: (id: number, action: "back" | "retry" | "continue_http" | "continue_threat") =>
    invoke<void>("interstitial_action", { id, action }),
  setSiteFiltering: (site: string, on: boolean, temporary: boolean) =>
    invoke<void>("site_filtering_set", { site, on, temporary }),
  setSiteLocal: (site: string, allowed: boolean, temporary: boolean) =>
    invoke<void>("site_local_set", { site, allowed, temporary }),
  setCustomDoh: (template: string, address: string) => invoke<SettingsView>("doh_custom_set", { template, address }),
  clearNetworkRecords: () => invoke<void>("network_records_clear"),
  /** M7: run the self-check in a separate test window; `onSelfCheckDone` reports the end. */
  selfCheckStart: () => invoke<void>("selftest_start"),
  selfCheckLast: () => invoke<SelfCheckLast>("selftest_last"),
  auditEntries: () => invoke<string[]>("audit_entries"),
  /** Resolves to the saved file's path, or null if the save dialog was cancelled. */
  auditExport: () => invoke<string | null>("audit_export"),
  reportSave: () => invoke<string | null>("report_save"),
  cookieSites: () => invoke<CookieSite[]>("cookie_sites"),
  /** Resolves to the number of the site's cookies still present afterwards (0 when it worked). */
  deleteSiteData: (site: string) => invoke<number>("site_data_delete", { site }),
  dataInventory: () => invoke<DataItem[]>("data_inventory"),
  /** Delete one inventory category now; resolves to what was done and how it was checked. */
  clearData: (id: string) => invoke<string>("data_clear", { id }),
  /** Check every enabled block list now; resolves to whether any list changed. */
  updateListsNow: () => invoke<boolean>("filters_update_now"),
  dismissNotice: (id: number) => invoke<void>("notice_dismiss", { id }),
  respond: (id: number, allow: boolean, remember = false) => invoke<void>("prompt_respond", { id, allow, remember }),
  resetPermission: (origin: string, permission: PermissionName) =>
    invoke<void>("permission_reset", { origin, permission }),
  showDownload: (id: number) => invoke<void>("download_show", { id }),
  cancelDownload: (id: number) => invoke<void>("download_cancel", { id }),
  clearDownloads: () => invoke<void>("downloads_clear"),
};

export const onTabs = (cb: (s: Snapshot) => void): Promise<UnlistenFn> =>
  listen<Snapshot>("tabs", (e) => cb(e.payload));

export const onAppUpdate = (cb: (s: AppUpdateStatus) => void): Promise<UnlistenFn> =>
  listen<AppUpdateStatus>("app-update", (e) => cb(e.payload));

export const onSelfCheckDone = (cb: (r: { ok: boolean; passed?: boolean; failed?: string[]; skipped?: string[]; error?: string }) => void): Promise<UnlistenFn> =>
  listen<{ ok: boolean; passed?: boolean; failed?: string[]; skipped?: string[]; error?: string }>("selftest-done", (e) => cb(e.payload));

export const onFocusAddress = (cb: () => void): Promise<UnlistenFn> => listen("focus-address", () => cb());

/** UNTRACE's own panel replaced the page: focus its main button. */
export const onFocusPanel = (cb: () => void): Promise<UnlistenFn> => listen("focus-panel", () => cb());

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : "Something went wrong.";
}
