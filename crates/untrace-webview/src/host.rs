//! Content host: one WebView2 environment, one container window, many tabs.
//!
//! Rules that keep this sound:
//! - Never hold a `RefCell` borrow while calling into WebView2 or the `notify` callback.
//! - Event handlers hold only a `Weak` reference and a tab id.
//! - Actions that could re-enter the runtime from inside its own event run via [`defer`].
//!
//! M2 security baseline (policy decisions live in `untrace_core::policy`):
//! - Top-level navigations pass the scheme gate and HTTPS-only upgrades.
//! - Failed navigations show UNTRACE's own panel in the UI (the page view is hidden meanwhile).
//! - Permission, external-application and download requests become prompts answered in the UI.
//!
//! M3 network filtering (`untrace_filter`):
//! - Every view raises `WebResourceRequested` for its documents' requests; exactly one view (the
//!   "worker owner") also raises shared/service-worker requests, which WebView2 reports to every
//!   registered view in the environment.
//! - Ads/trackers are answered with an empty 403; malware/phishing pages are cancelled at
//!   `NavigationStarting` and replaced by UNTRACE's warning panel (D-033).
//!
//! M4 privacy controls:
//! - Tracking prevention level per profile, read back from the engine.
//! - Tracking parameters are removed from page and frame GET requests by answering them with a
//!   redirect to the cleaned address (D-027), so neither the server nor page scripts see them.
//! - Temporary tabs share one InPrivate profile with a random name (D-028); it is discarded when
//!   the last temporary tab closes.
//! - Cookies and site data of the standard profile can be listed and deleted per site.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
    hash::{BuildHasher, Hasher},
    path::{Path, PathBuf},
    rc::{Rc, Weak},
};

use serde::Serialize;
use untrace_core::{
    policy::{self, BlockReason, DownloadRisk, ExternalDecision, HttpsOnly, NavDecision, Permission, PermissionPolicy},
    registry::{Applier, Observed, Value},
};
use untrace_filter::{
    Filters, ListId, ResourceKind,
    cosmetic::{GenericMode, ScriptOptions},
    registrable_domain,
};
use webview2_com::{Microsoft::Web::WebView2::Win32::*, *};
use windows::{
    Win32::{
        Foundation::*,
        UI::{Input::KeyboardAndMouse::*, WindowsAndMessaging::*},
    },
    core::*,
};

use untrace_net::{Proxy, Space, Via, addr as netaddr};

use crate::{com, container, container::defer, dialog};

pub const DEVTOOLS_ID: &str = "browser.devtools";
pub const HTTPS_ONLY_ID: &str = "security.https_only";
pub const TRACKING_PREVENTION_ID: &str = "privacy.tracking_prevention";
pub const STRIP_PARAMS_ID: &str = "privacy.strip_tracking_params";
/// D-040: parts of public sites may not reach this computer or the local network.
pub const LOCAL_NETWORK_ID: &str = "security.local_network";
/// M6: hide the elements blocked ads leave behind (cosmetic filtering, D-015).
pub const HIDE_ELEMENTS_ID: &str = "filter.hide_elements";
/// M8 (D-052): WebRTC only through the network layer. An engine preference set in each
/// profile before the engine loads it; takes effect at the next start.
pub const WEBRTC_ID: &str = "network.webrtc_in_network_layer";
/// Pages never wait longer than this for a new tab's hiding script.
const COSMETIC_WAIT_MS: u32 = 3_000;
/// How long the first pages wait for the network layer's start-up check (D-026).
const NETWORK_CHECK_MS: u32 = 5_000;
/// Tracking prevention levels, in the engine's order (0–3).
pub const TRACKING_LEVELS: [&str; 4] = ["off", "basic", "balanced", "strict"];
/// Prefix of temporary profile names; the rest is random (D-028).
pub const TEMP_PROFILE_PREFIX: &str = "temp-";
const MAX_PARAM_NAMES: usize = 20;
/// Oldest WebView2 Runtime major version UNTRACE accepts (all APIs used exist from here on).
pub const MIN_RUNTIME_MAJOR: u32 = 130;
const FAVICON_LIMIT: usize = 64 * 1024;
const MAX_PROMPTS_PER_TAB: usize = 3;

#[derive(Clone, Debug)]
pub struct HostConfig {
    /// WebView2 user-data folder for content (separate from the UI view's).
    pub data_dir: PathBuf,
    pub profile: String,
    pub devtools: bool,
    pub https_only: bool,
    /// Background shown before a page paints (RGB).
    pub background: [u8; 3],
    /// M5 network layer: every request of the engine goes through this proxy (D-006).
    pub network: Option<Proxy>,
    /// D-052: keep WebRTC inside the network layer (applied only together with `network`).
    pub webrtc_proxy_only: bool,
}

/// D-053: the light/dark preference pages see (`prefers-color-scheme`). `Auto` follows Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum PageColorScheme {
    #[default]
    Auto,
    Light,
    Dark,
}

pub enum HostEvent {
    /// Tabs or engine state changed; read a fresh [`Snapshot`].
    Changed,
    /// The user pressed Ctrl+L / Alt+D / F6 (or opened a new tab) inside content.
    FocusAddress,
    /// UNTRACE's own panel replaced the active page; keyboard focus must move to the UI.
    FocusPanel,
    /// The user pressed Ctrl+D inside content: bookmark the page (D-055).
    Bookmark,
}

pub type Notify = Rc<dyn Fn(HostEvent)>;

// ------------------------------------------------------------------- types

/// Per-page counts of what UNTRACE refused (reset when a new page starts loading). Kept in
/// memory only (D-014).
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Blocked {
    pub permissions: u32,
    pub popups: u32,
    pub external_apps: u32,
    pub certificate_errors: u32,
    pub navigations: u32,
    /// Requests blocked by the ads/trackers lists.
    pub requests: u32,
    /// Requests to malware/phishing hosts blocked inside the page.
    pub threats: u32,
    /// Hosts with blocked requests (at most [`MAX_BLOCKED_HOSTS`]).
    pub hosts: Vec<BlockedHost>,
    /// Tracking parameters removed from this page's and its frames' addresses (D-027).
    pub params: u32,
    /// Their names, each once (at most 20).
    pub param_names: Vec<String>,
    /// Requests from this public page to this computer or the local network (D-040).
    pub local_network: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockedHost {
    pub host: String,
    pub count: u32,
    /// Set when the host is on a malware or phishing list.
    pub threat: Option<ListId>,
    /// Blocked because it is on this computer or the local network (D-040).
    pub local: bool,
}

pub const MAX_BLOCKED_HOSTS: usize = 100;

impl Blocked {
    fn add_host(&mut self, host: String, threat: Option<ListId>, local: bool) {
        if let Some(h) = self.hosts.iter_mut().find(|h| h.host == host) {
            h.count += 1;
        } else if self.hosts.len() < MAX_BLOCKED_HOSTS {
            self.hosts.push(BlockedHost {
                host,
                count: 1,
                threat,
                local,
            });
        }
    }

    fn add_params(&mut self, names: &[String]) {
        self.params += names.len() as u32;
        for n in names {
            if self.param_names.len() < MAX_PARAM_NAMES && !self.param_names.contains(n) {
                self.param_names.push(n.clone());
            }
        }
    }
}

/// Sites (registrable domains) with cookies in the standard profile.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieSite {
    pub site: String,
    pub cookies: u32,
    /// Cookie domains under this site (e.g. "www.example.com", "example.com").
    pub hosts: Vec<String>,
}

/// What [`ContentHost::clear_data`] removes from the standard profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClearKinds {
    /// Cookies, local storage, IndexedDB, cache storage, service workers, file systems.
    pub site_data: bool,
    /// The HTTP disk cache.
    pub cache: bool,
    /// Browsing and download history (UNTRACE shows none; the engine keeps it).
    pub history: bool,
    /// Site settings: saved permission decisions and the engine's per-site records.
    pub site_settings: bool,
}

impl ClearKinds {
    fn engine_kinds(self) -> COREWEBVIEW2_BROWSING_DATA_KINDS {
        let mut k = 0;
        if self.site_data {
            k |= COREWEBVIEW2_BROWSING_DATA_KINDS_ALL_SITE.0 | COREWEBVIEW2_BROWSING_DATA_KINDS_SERVICE_WORKERS.0;
        }
        if self.cache {
            k |= COREWEBVIEW2_BROWSING_DATA_KINDS_DISK_CACHE.0;
        }
        if self.history {
            k |= COREWEBVIEW2_BROWSING_DATA_KINDS_BROWSING_HISTORY.0
                | COREWEBVIEW2_BROWSING_DATA_KINDS_DOWNLOAD_HISTORY.0;
        }
        if self.site_settings {
            k |= COREWEBVIEW2_BROWSING_DATA_KINDS_SETTINGS.0;
        }
        COREWEBVIEW2_BROWSING_DATA_KINDS(k)
    }

    pub fn is_empty(self) -> bool {
        !(self.site_data || self.cache || self.history || self.site_settings)
    }
}

/// A random profile name that carries no information (D-028).
fn random_profile_name() -> String {
    let mut s = String::from(TEMP_PROFILE_PREFIX);
    for _ in 0..2 {
        // RandomState is seeded from the OS random source; each instance gives fresh keys.
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
        );
        s.push_str(&format!("{:016x}", h.finish()));
    }
    s
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    /// Seconds since the Unix epoch.
    pub valid_from: Option<f64>,
    pub valid_to: Option<f64>,
}

/// A page UNTRACE shows instead of the web page (rendered by the trusted UI).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Interstitial {
    /// HTTPS-only: the secure version of an http:// address could not be loaded.
    HttpsUnavailable {
        url: String,
        http_url: String,
        host: String,
        reason: String,
    },
    /// The certificate was rejected; there is no way to continue (D-008).
    Certificate {
        url: String,
        host: String,
        reason: String,
        certificate: Option<CertInfo>,
    },
    LoadError {
        url: String,
        host: String,
        reason: String,
    },
    /// The site is on a malware or phishing list (D-033); "Continue anyway" lasts the session.
    Threat {
        url: String,
        host: String,
        list: ListId,
        list_title: String,
        list_homepage: String,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PromptDetail {
    Permission {
        permission: Permission,
        label: String,
        phrase: String,
    },
    ExternalApp {
        scheme: String,
        target: String,
    },
    Download {
        file_name: String,
        size: Option<i64>,
        risk: DownloadRisk,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptInfo {
    pub id: u32,
    pub origin: String,
    pub detail: PromptDetail,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TabInfo {
    pub id: u32,
    pub title: String,
    pub url: String,
    pub loading: bool,
    pub can_go_back: bool,
    pub can_go_forward: bool,
    pub favicon: Option<String>,
    pub crashed: bool,
    pub ready: bool,
    /// Why the last top-level navigation failed, if it did.
    pub last_error: Option<String>,
    /// HTTP status of the last top-level navigation, when the engine reports one.
    pub http_status: Option<i32>,
    /// What UNTRACE refused on the current page.
    pub blocked: Blocked,
    pub interstitial: Option<Interstitial>,
    /// Questions waiting for the user (permissions, other applications, downloads).
    pub prompts: Vec<PromptInfo>,
    /// One-line explanation of the last thing UNTRACE refused without asking.
    pub notice: Option<String>,
    /// Connection security as the engine reports it (read back, not assumed).
    pub connection: Option<ConnectionInfo>,
    /// The site (registrable domain) of the page, for per-site settings.
    pub site: Option<String>,
    /// A temporary tab: InPrivate profile, nothing kept after the last temporary tab closes.
    pub temporary: bool,
    /// How the page's own address was reached, from the network layer (M5).
    pub network: Option<PageNetwork>,
    /// An empty tab the user opened (no address yet, or `about:blank`), not a page's pop-up.
    /// Its page view is hidden and the UI draws the area in the theme's background: in dark
    /// mode the engine paints blank pages its own grey.
    pub new_tab_page: bool,
}

/// The network layer's view of a page's host (read from the proxy's record, not assumed).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageNetwork {
    /// The network layer opened a connection to this host this session.
    pub through_network_layer: bool,
    /// How the name was resolved.
    pub dns: Option<Via>,
    /// DNS-over-HTTPS server, when encrypted.
    pub dns_server: Option<String>,
}

/// The network layer's start-up check: a request from the engine must reach the proxy with
/// this launch's credentials (D-006, D-026).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum NetworkCheck {
    Off,
    NotRun,
    Pending,
    Passed { ms: u32 },
    Failed { reason: String },
}

/// The engine's own security verdict for a page, from the DevTools protocol
/// (`Security.visibleSecurityStateChanged`). Host-side only; pages cannot see this channel.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInfo {
    /// Origin of the page this state belongs to.
    pub origin: String,
    /// "secure" | "neutral" | "insecure" | "insecure-broken" | "info" | "unknown"
    pub state: String,
    pub protocol: Option<String>,
    pub key_exchange: Option<String>,
    pub cipher: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    /// Seconds since the Unix epoch.
    pub valid_from: Option<f64>,
    pub valid_to: Option<f64>,
}

impl ConnectionInfo {
    fn from_cdp(origin: String, json: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(json).ok()?;
        let s = &v["visibleSecurityState"];
        let c = &s["certificateSecurityState"];
        let text = |x: &serde_json::Value| x.as_str().filter(|t| !t.is_empty()).map(str::to_string);
        Some(Self {
            origin,
            state: text(&s["securityState"]).unwrap_or_else(|| "unknown".into()),
            protocol: text(&c["protocol"]),
            key_exchange: text(&c["keyExchangeGroup"]).or_else(|| text(&c["keyExchange"])),
            cipher: text(&c["cipher"]),
            subject: text(&c["subjectName"]),
            issuer: text(&c["issuer"]),
            valid_from: c["validFrom"].as_f64(),
            valid_to: c["validTo"].as_f64(),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadInfo {
    pub id: u32,
    pub file_name: String,
    pub path: String,
    /// "in_progress" | "completed" | "interrupted"
    pub state: String,
    pub received: i64,
    pub total: Option<i64>,
    pub risk: DownloadRisk,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredPermission {
    pub origin: String,
    pub permission: Permission,
    pub label: String,
    /// "allow" | "deny"
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub tabs: Vec<TabInfo>,
    pub active: Option<u32>,
    pub runtime_version: Option<String>,
    pub engine_error: Option<String>,
    pub engine_update_available: bool,
    pub downloads: Vec<DownloadInfo>,
    /// Permission decisions saved in the profile ("remember for this site").
    pub stored_permissions: Vec<StoredPermission>,
    /// Sites where the user turned ads/trackers blocking off.
    pub site_exceptions: Vec<String>,
    /// The same, made in temporary tabs: this temporary session only, never saved.
    pub temp_site_exceptions: Vec<String>,
    /// Sites allowed to reach this computer and the local network (D-040).
    pub local_network_sites: Vec<String>,
    /// The same, made in temporary tabs (never saved).
    pub temp_local_network_sites: Vec<String>,
}

/// Engine facts for Diagnostics. Read back from the runtime unless stated otherwise.
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EngineInfo {
    pub runtime_version: Option<String>,
    pub minimum_runtime_major: u32,
    pub engine_error: Option<String>,
    pub update_available: bool,
    pub profile: String,
    pub data_dir: String,
    pub tracking_prevention_enabled: bool,
    pub tracking_prevention_level: Option<String>,
    /// Set when UNTRACE starts the engine; WebView2 offers no read-back for this option.
    pub crash_reports_local: Option<bool>,
    /// Experiment (D-003): content views share the UI view's environment, created by Tauri.
    pub shared_environment: bool,
    pub crash_report_folder: Option<String>,
    pub browser_arguments: String,
    pub web_messages_enabled: Option<bool>,
    pub host_objects_allowed: Option<bool>,
    pub smartscreen_enabled: Option<bool>,
    pub password_autosave_enabled: Option<bool>,
    pub autofill_enabled: Option<bool>,
    pub builtin_error_pages_enabled: Option<bool>,
    pub history_cleared_at_start: Option<bool>,
    pub https_only: bool,
    pub https_session_exceptions: usize,
    pub open_tabs: usize,
    /// Request filtering is registered on every open tab (false if the runtime refused).
    pub request_filtering_registered: bool,
    /// Tab that also receives shared/service-worker requests.
    pub worker_requests_tab: Option<u32>,
    /// Worker requests blocked this session (they belong to no single page).
    pub worker_requests_blocked: u32,
    /// Hosts the user chose to continue to despite a malware/phishing warning (this session).
    pub threat_session_exceptions: usize,
    /// Tracking prevention level of the temporary profile, when temporary tabs are open.
    pub temp_tracking_prevention_level: Option<String>,
    pub temporary_tabs: usize,
    pub strip_tracking_params: bool,
    /// The engine was started with the network layer's proxy arguments.
    pub network_layer: bool,
    pub network_check: Option<NetworkCheck>,
    pub local_network_protection: bool,
    /// D-052: WebRTC only through the network layer (None: no network layer running).
    pub webrtc_proxy_only: Option<std::result::Result<bool, String>>,
    /// Worker requests to this computer or the local network blocked this session.
    pub local_network_worker_blocked: u32,
    /// M6 element hiding: switch, tabs carrying the script, its size, and the rules behind it.
    pub hide_elements: bool,
    pub hide_elements_tabs: usize,
    pub hide_elements_script_bytes: usize,
    pub cosmetic_rules: Option<untrace_filter::cosmetic::CosmeticStats>,
}

fn web_error_name(status: i32) -> &'static str {
    match status {
        1 => "The certificate is for a different site.",
        2 => "The certificate has expired.",
        3 => "The client certificate contains errors.",
        4 => "The certificate has been revoked.",
        5 => "The certificate is not valid.",
        6 => "The server could not be reached.",
        7 => "The connection timed out.",
        8 => "The server sent an invalid response.",
        9 => "The connection was aborted.",
        10 => "The connection was reset.",
        11 => "The network connection was lost.",
        12 => "Could not connect to the server.",
        13 => "The address could not be found.",
        14 => "The navigation was cancelled.",
        15 => "Too many or invalid redirects.",
        16 => "An unexpected error occurred.",
        17 => "The site asks for a user name and password.",
        18 => "The proxy asks for a user name and password.",
        _ => "The page could not be loaded.",
    }
}

fn permission_from(kind: i32) -> Permission {
    match kind {
        1 => Permission::Microphone,
        2 => Permission::Camera,
        3 => Permission::Geolocation,
        4 => Permission::Notifications,
        5 => Permission::OtherSensors,
        6 => Permission::ClipboardRead,
        7 => Permission::MultipleAutomaticDownloads,
        8 => Permission::FileReadWrite,
        9 => Permission::Autoplay,
        10 => Permission::LocalFonts,
        11 => Permission::MidiSysex,
        12 => Permission::WindowManagement,
        _ => Permission::Unknown,
    }
}

fn permission_kind(p: Permission) -> COREWEBVIEW2_PERMISSION_KIND {
    COREWEBVIEW2_PERMISSION_KIND(match p {
        Permission::Microphone => 1,
        Permission::Camera => 2,
        Permission::Geolocation => 3,
        Permission::Notifications => 4,
        Permission::OtherSensors => 5,
        Permission::ClipboardRead => 6,
        Permission::MultipleAutomaticDownloads => 7,
        Permission::FileReadWrite => 8,
        Permission::Autoplay => 9,
        Permission::LocalFonts => 10,
        Permission::MidiSysex => 11,
        Permission::WindowManagement => 12,
        Permission::Unknown => 0,
    })
}

fn origin_of(uri: &str) -> String {
    url::Url::parse(uri)
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_else(|_| "this page".into())
}

fn host_of(uri: &str) -> String {
    url::Url::parse(uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default()
}

fn shorten(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "…"
    }
}

/// WebView2 resource context → filter request type.
fn resource_kind(ctx: i32) -> ResourceKind {
    match ctx {
        1 => ResourceKind::Subdocument, // the top-level document never reaches the filter
        2 => ResourceKind::Stylesheet,
        3 => ResourceKind::Image,
        4 | 9 => ResourceKind::Media,
        5 => ResourceKind::Font,
        6 => ResourceKind::Script,
        7 | 8 | 10 => ResourceKind::Xhr,
        11 => ResourceKind::WebSocket,
        14 => ResourceKind::Ping,
        _ => ResourceKind::Other,
    }
}

/// Schemes that load a page in the tab (everything else hands off or is refused).
fn is_web_scheme(uri: &str) -> bool {
    matches!(
        policy::scheme_of(uri).as_str(),
        "http" | "https" | "about" | "data" | "blob"
    )
}

/// A request from the engine to the network layer's check name. The proxy never resolves it
/// and answers 403; seeing it with credentials proves the engine's traffic reaches the proxy.
fn send_probe(wv: &ICoreWebView2, name: &str) {
    let js = format!(
        "fetch('https://{name}/', {{ mode: 'no-cors', cache: 'no-store', credentials: 'omit' }}).catch(() => 0); 0"
    );
    let h = ExecuteScriptCompletedHandler::create(Box::new(|_, _| Ok(())));
    // SAFETY: COM call on a live webview with a valid script string.
    unsafe {
        let _ = wv.ExecuteScript(&HSTRING::from(js), &h);
    }
}

fn runtime_major(version: &str) -> Option<u32> {
    version.split('.').next()?.trim().parse().ok()
}

// ------------------------------------------------------------------- state

type OnReady = Box<dyn FnOnce(&ICoreWebView2)>;
/// What a new tab does once its hiding script is in place (M6).
type AfterCosmetic = Box<dyn FnOnce(&ContentHost)>;

struct Upgrade {
    https_url: String,
    http_url: String,
    hops: u8,
}

struct Tab {
    info: TabInfo,
    /// Opened by a page (a pop-up), not by the user. A page can write into its own blank
    /// pop-up, so such a tab is never treated as an empty new tab.
    from_page: bool,
    controller: Option<ICoreWebView2Controller>,
    webview: Option<ICoreWebView2>,
    pending_url: Option<String>,
    on_ready: Option<OnReady>,
    /// URL of the top-level navigation in progress.
    nav_uri: String,
    upgrade: Option<Upgrade>,
    /// Engine id of that navigation; completion events for other ids are not this page's.
    nav_id: u64,
    /// Certificate error UNTRACE refused during this navigation: (reason, certificate).
    cert_error: Option<(String, Option<CertInfo>)>,
    /// Tracking parameters removed from the address now loading: (cleaned address, names).
    /// Carried over the redirect, which starts the navigation again.
    cleaned: Option<(String, Vec<String>)>,
    /// Addresses of navigations UNTRACE cancelled (warning, HTTPS-only upgrade, blocked link).
    /// The engine still sends a cancelled navigation's request (M5 probe), so the request event
    /// answers it with 403: nothing leaves.
    cancelled: Vec<String>,
    /// M6: the element-hiding script registered on this view.
    cosmetic: CosmeticState,
    /// Bumped on every (re-)registration; a late result for an older one is removed again.
    cosmetic_gen: u64,
    /// M6: the small script with the current site's own hiding rules.
    site: Option<SiteRules>,
    site_gen: u64,
}

/// One site's own hiding rules, registered for the site a tab is on (D-045).
#[derive(Debug, Clone)]
struct SiteRules {
    host: String,
    script: Rc<String>,
    state: CosmeticState,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum CosmeticState {
    #[default]
    None,
    /// Handed to the engine, id not reported yet.
    Pending,
    Registered(String),
}

/// Request and navigation addresses compare without their fragment.
fn without_fragment(u: &str) -> &str {
    u.split('#').next().unwrap_or(u)
}

const MAX_CANCELLED: usize = 8;

impl Tab {
    fn note_cancelled(&mut self, uri: &str) {
        if self.cancelled.len() >= MAX_CANCELLED {
            self.cancelled.remove(0);
        }
        self.cancelled.push(without_fragment(uri).to_string());
    }

    /// Was this request's navigation cancelled by UNTRACE? Consumes the entry.
    fn take_cancelled(&mut self, uri: &str) -> bool {
        let u = without_fragment(uri);
        match self.cancelled.iter().position(|c| c == u) {
            Some(i) => {
                self.cancelled.remove(i);
                true
            }
            None => false,
        }
    }
}

enum PendingArgs {
    Permission(ICoreWebView2PermissionRequestedEventArgs),
    External(ICoreWebView2LaunchingExternalUriSchemeEventArgs),
    Download {
        args: ICoreWebView2DownloadStartingEventArgs,
        suggested: PathBuf,
        risk: DownloadRisk,
    },
}

struct Pending {
    id: u32,
    tab: u32,
    deferral: ICoreWebView2Deferral,
    args: PendingArgs,
}

struct Inner {
    parent: HWND,
    container: HWND,
    cfg: HostConfig,
    env: Option<ICoreWebView2Environment>,
    runtime_version: Option<String>,
    engine_error: Option<String>,
    update_available: bool,
    tabs: Vec<Tab>,
    active: Option<u32>,
    next_id: u32,
    rect: RECT,
    visible: bool,
    notify: Notify,
    history_cleared: Option<bool>,
    history_clear_started: bool,
    shared_env: bool,
    https: HttpsOnly,
    pending: Vec<Pending>,
    next_prompt: u32,
    downloads: Vec<(DownloadInfo, Option<ICoreWebView2DownloadOperation>)>,
    next_download: u32,
    stored_permissions: Vec<StoredPermission>,
    /// SELF-CHECK ONLY: save downloads here instead of asking with the Windows dialog.
    test_download_dir: Option<PathBuf>,
    /// What requests and navigations are matched against (swapped when lists change).
    filters: Rc<Filters>,
    /// Sites (registrable domains) with ads/trackers blocking turned off by the user.
    site_exceptions: HashSet<String>,
    /// Hosts the user continued to despite a malware/phishing warning; this session only.
    threat_exceptions: HashSet<String>,
    /// Tab whose view also raises shared/service-worker requests.
    worker_owner: Option<u32>,
    worker_blocked: u32,
    /// The runtime refused to register request filtering on some tab.
    filter_registration_failed: bool,
    /// Second worker owner, for the temporary profile's workers.
    temp_worker_owner: Option<u32>,
    /// Requested tracking prevention level (index into [`TRACKING_LEVELS`]).
    tracking_level: i32,
    /// D-027: remove tracking parameters from page and frame addresses.
    strip_params: bool,
    /// The standard profile, kept once the first standard tab has delivered it.
    std_profile: Option<ICoreWebView2Profile>,
    /// The temporary session: random profile name, and the profile once a tab delivered it.
    temp_profile: Option<(String, Option<ICoreWebView2Profile>)>,
    /// D-052: the WebRTC policy as written to the standard profile before the engine started
    /// (true = only through the network layer), or why it could not be written.
    webrtc: std::result::Result<bool, String>,
    /// The same for the current temporary session's profile.
    webrtc_temp: Option<std::result::Result<bool, String>>,
    /// D-053: the colour scheme pages are told (applied to every profile as it appears).
    color_scheme: PageColorScheme,
    /// Self-check only: hosts answered from local folders by the request handler.
    served: HashMap<String, PathBuf>,
    /// Per-site blocking exceptions made in temporary tabs (never saved).
    temp_site_exceptions: HashSet<String>,
    /// Browsing data to remove from the standard profile before the first page loads (the
    /// previous session did not finish clearing on exit).
    startup_clear: ClearKinds,
    /// First pages wait for the start-up clearing.
    startup_clear_done: bool,
    held_navigations: Vec<(u32, String)>,
    /// D-040 on/off, and the sites allowed to reach the local network.
    local_protect: bool,
    local_sites: HashSet<String>,
    temp_local_sites: HashSet<String>,
    local_worker_blocked: u32,
    network_check: NetworkCheck,
    network_check_started: bool,
    /// M6: hiding on/off, and the generated scripts (normal tabs, temporary tabs).
    cosmetic_on: bool,
    cosmetic_scripts: [Option<Rc<String>>; 2],
    /// MEASUREMENT ONLY (compat runner): leave out the per-site script and its fallback.
    cosmetic_site_rules: bool,
}

#[derive(Clone)]
pub struct ContentHost {
    inner: Rc<RefCell<Inner>>,
}

fn upgrade(w: &Weak<RefCell<Inner>>) -> Option<ContentHost> {
    w.upgrade().map(|inner| ContentHost { inner })
}

fn blank_info(id: u32) -> TabInfo {
    TabInfo {
        id,
        title: String::new(),
        url: String::new(),
        loading: false,
        can_go_back: false,
        can_go_forward: false,
        favicon: None,
        crashed: false,
        ready: false,
        last_error: None,
        http_status: None,
        blocked: Blocked::default(),
        interstitial: None,
        prompts: Vec::new(),
        notice: None,
        connection: None,
        site: None,
        temporary: false,
        network: None,
        new_tab_page: false,
    }
}

/// An address that shows nothing: a tab that has not loaded yet, or the engine's blank page.
fn is_blank_address(url: &str) -> bool {
    url.is_empty() || url == "about:blank"
}

fn take_str(f: impl FnOnce(&mut PWSTR) -> windows::core::Result<()>) -> Option<String> {
    let mut p = PWSTR::null();
    f(&mut p).ok().map(|_| com::take(p))
}

impl ContentHost {
    /// Create the container under `parent` and start a dedicated content environment (asynchronous).
    pub fn new(parent: HWND, cfg: HostConfig, notify: Notify) -> std::result::Result<Self, String> {
        let host = Self::build(parent, cfg, notify, false)?;
        host.create_environment()?;
        Ok(host)
    }

    /// EXPERIMENT (D-003): host content views in an existing environment (the UI view's, created
    /// by Tauri) instead of a dedicated one. Content still uses its own profile.
    pub fn with_environment(
        parent: HWND,
        cfg: HostConfig,
        notify: Notify,
        env: ICoreWebView2Environment,
    ) -> std::result::Result<Self, String> {
        let host = Self::build(parent, cfg, notify, true)?;
        host.on_environment(env);
        Ok(host)
    }

    fn build(parent: HWND, cfg: HostConfig, notify: Notify, shared_env: bool) -> std::result::Result<Self, String> {
        let container = container::create(parent).map_err(|e| format!("content container: {}", e.message()))?;
        let https = HttpsOnly {
            enabled: cfg.https_only,
            ..Default::default()
        };
        Ok(ContentHost {
            inner: Rc::new(RefCell::new(Inner {
                parent,
                container,
                cfg,
                env: None,
                runtime_version: None,
                engine_error: None,
                update_available: false,
                tabs: Vec::new(),
                active: None,
                next_id: 1,
                rect: RECT::default(),
                visible: false,
                notify,
                history_cleared: None,
                history_clear_started: false,
                shared_env,
                https,
                pending: Vec::new(),
                next_prompt: 1,
                downloads: Vec::new(),
                next_download: 1,
                stored_permissions: Vec::new(),
                test_download_dir: None,
                filters: Rc::new(Filters::default()),
                site_exceptions: HashSet::new(),
                threat_exceptions: HashSet::new(),
                worker_owner: None,
                worker_blocked: 0,
                filter_registration_failed: false,
                temp_worker_owner: None,
                tracking_level: 2,
                strip_params: true,
                std_profile: None,
                temp_profile: None,
                webrtc: Err("not set yet".into()),
                webrtc_temp: None,
                color_scheme: PageColorScheme::Auto,
                served: HashMap::new(),
                temp_site_exceptions: HashSet::new(),
                startup_clear: ClearKinds::default(),
                startup_clear_done: false,
                held_navigations: Vec::new(),
                local_protect: true,
                local_sites: HashSet::new(),
                temp_local_sites: HashSet::new(),
                local_worker_blocked: 0,
                network_check: NetworkCheck::NotRun,
                network_check_started: false,
                cosmetic_on: true,
                cosmetic_scripts: [None, None],
                cosmetic_site_rules: true,
            })),
        })
    }

    // -------------------------------------------------------------- filtering

    /// Replace the filters requests are matched against (lists switched on/off or updated).
    pub fn set_filters(&self, filters: Filters) {
        if let Some(p) = self.proxy() {
            p.set_threats(filters.shared_threats()); // D-042: the network backstop
        }
        self.inner.borrow_mut().filters = Rc::new(filters);
        self.refresh_cosmetic();
        self.changed();
    }

    // -------------------------------------------------------------- element hiding (M6)

    /// The hiding script for normal or temporary tabs, generated once per change of lists,
    /// switch or site exceptions. `None` when hiding is off or there is nothing to hide.
    fn cosmetic_script(&self, temporary: bool) -> Option<Rc<String>> {
        let mut i = self.inner.borrow_mut();
        if !i.cosmetic_on {
            return None;
        }
        let rules = i.filters.cosmetic()?.clone();
        if rules.is_empty() {
            return None;
        }
        let slot = usize::from(temporary);
        if let Some(s) = &i.cosmetic_scripts[slot] {
            return Some(s.clone());
        }
        // The user's per-site "Block ads and trackers" switch turns hiding off there too.
        let mut off: Vec<String> = i.site_exceptions.iter().cloned().collect();
        if temporary {
            off.extend(i.temp_site_exceptions.iter().cloned());
        }
        off.sort();
        off.dedup();
        let s = Rc::new(rules.script(&ScriptOptions {
            generic: GenericMode::Observe,
            off_sites: off,
            debug: false,
            embed_site_rules: false,
        }));
        i.cosmetic_scripts[slot] = Some(s.clone());
        Some(s)
    }

    /// Give one tab the current hiding script (removing the previous one). `then` runs once the
    /// engine has accepted it, or after `COSMETIC_WAIT_MS` at the latest; new pages wait for it
    /// so that their first document is covered.
    fn register_cosmetic(&self, id: u32, then: Option<AfterCosmetic>) {
        let Some((wv, temporary, old, generation)) = self.with_tab(id, |t| {
            t.cosmetic_gen += 1;
            (
                t.webview.clone(),
                t.info.temporary,
                std::mem::take(&mut t.cosmetic),
                t.cosmetic_gen,
            )
        }) else {
            if let Some(f) = then {
                f(self);
            }
            return;
        };
        let Some(wv) = wv else {
            if let Some(f) = then {
                f(self);
            }
            return;
        };
        if let CosmeticState::Registered(old) = old {
            // SAFETY: COM call on a live webview.
            unsafe {
                let _ = wv.RemoveScriptToExecuteOnDocumentCreated(&HSTRING::from(old.as_str()));
            }
        }
        let Some(script) = self.cosmetic_script(temporary) else {
            if let Some(f) = then {
                f(self);
            }
            return;
        };
        let once: Rc<RefCell<Option<AfterCosmetic>>> = Rc::new(RefCell::new(then));
        let weak = self.weak();
        let once2 = once.clone();
        let wv2 = wv.clone();
        let handler = AddScriptToExecuteOnDocumentCreatedCompletedHandler::create(Box::new(move |hr, sid| {
            if let Some(host) = upgrade(&weak) {
                let current = host
                    .with_tab(id, |t| {
                        let current = t.cosmetic_gen == generation;
                        if current && hr.is_ok() {
                            t.cosmetic = CosmeticState::Registered(sid.clone());
                        } else if current {
                            t.cosmetic = CosmeticState::None;
                        }
                        current
                    })
                    .unwrap_or(false);
                if !current && hr.is_ok() {
                    // Superseded while it was being added: take it out again.
                    // SAFETY: COM call on a live webview.
                    unsafe {
                        let _ = wv2.RemoveScriptToExecuteOnDocumentCreated(&HSTRING::from(sid.as_str()));
                    }
                }
                let f = once2.borrow_mut().take();
                if let Some(f) = f {
                    f(&host);
                }
                host.changed();
            }
            Ok(())
        }));
        // SAFETY: COM call on a live webview with a valid script string.
        let accepted =
            unsafe { wv.AddScriptToExecuteOnDocumentCreated(&HSTRING::from(script.as_str()), &handler) }.is_ok();
        if accepted {
            self.with_tab(id, |t| t.cosmetic = CosmeticState::Pending);
        }
        let f = if accepted { None } else { once.borrow_mut().take() };
        if let Some(f) = f {
            f(self);
            return;
        }
        let weak = self.weak();
        container::defer_after(COSMETIC_WAIT_MS, move || {
            if let Some(host) = upgrade(&weak) {
                let f = once.borrow_mut().take();
                if let Some(f) = f {
                    f(&host);
                }
            }
        });
    }

    /// Lists, switch or site exceptions changed: regenerate and replace the script on every
    /// tab. Pages already open keep what they had until they reload.
    fn refresh_cosmetic(&self) {
        let ids: Vec<u32> = {
            let mut i = self.inner.borrow_mut();
            i.cosmetic_scripts = [None, None];
            i.tabs
                .iter()
                .filter(|t| t.webview.is_some())
                .map(|t| t.info.id)
                .collect()
        };
        for id in ids {
            self.drop_site_rules(id);
            self.register_cosmetic(id, None);
        }
    }

    /// Unregister a tab's per-site script (it is prepared again on the next navigation).
    fn drop_site_rules(&self, id: u32) {
        let Some((wv, old)) = self.with_tab(id, |t| {
            t.site_gen += 1;
            (t.webview.clone(), t.site.take())
        }) else {
            return;
        };
        if let (
            Some(wv),
            Some(SiteRules {
                state: CosmeticState::Registered(sid),
                ..
            }),
        ) = (wv, old)
        {
            // SAFETY: COM call on a live webview.
            unsafe {
                let _ = wv.RemoveScriptToExecuteOnDocumentCreated(&HSTRING::from(sid.as_str()));
            }
        }
    }

    /// A top-level navigation to `uri` starts: give the tab that site's own hiding rules, in a
    /// small script of their own (the script every document gets carries only generic rules,
    /// which keeps it about three times smaller, M6). If the registration finishes after the
    /// page's document was created, `on_content_loading` applies the same rules a moment later.
    fn prepare_site_rules(&self, id: u32, uri: &str) {
        if !self.inner.borrow().cosmetic_site_rules {
            return;
        }
        let host = host_of(uri).to_ascii_lowercase();
        let current = self.tab_ref(id, |t| t.site.as_ref().map(|s| s.host.clone())).flatten();
        if current.as_deref() == Some(host.as_str()) {
            return;
        }
        self.drop_site_rules(id);
        let css = {
            let i = self.inner.borrow();
            let temporary = i.tabs.iter().any(|t| t.info.id == id && t.info.temporary);
            let excepted = registrable_domain(uri)
                .is_some_and(|s| i.site_exceptions.contains(&s) || (temporary && i.temp_site_exceptions.contains(&s)));
            if !i.cosmetic_on || excepted || host.is_empty() {
                None
            } else {
                i.filters.cosmetic().and_then(|r| r.site_css(&host))
            }
        };
        let Some(css) = css else { return };
        let script = Rc::new(untrace_filter::cosmetic::site_script(&host, &css));
        let Some((wv, generation)) = self.with_tab(id, |t| {
            t.site_gen += 1;
            t.site = Some(SiteRules {
                host: host.clone(),
                script: script.clone(),
                state: CosmeticState::Pending,
            });
            (t.webview.clone(), t.site_gen)
        }) else {
            return;
        };
        let Some(wv) = wv else { return };
        let weak = self.weak();
        let wv2 = wv.clone();
        let handler = AddScriptToExecuteOnDocumentCreatedCompletedHandler::create(Box::new(move |hr, sid| {
            if let Some(h) = upgrade(&weak) {
                let current = h
                    .with_tab(id, |t| {
                        let current = t.site_gen == generation;
                        if current && let Some(s) = t.site.as_mut() {
                            s.state = if hr.is_ok() {
                                CosmeticState::Registered(sid.clone())
                            } else {
                                CosmeticState::None
                            };
                        }
                        current
                    })
                    .unwrap_or(false);
                if !current && hr.is_ok() {
                    // SAFETY: COM call on a live webview.
                    unsafe {
                        let _ = wv2.RemoveScriptToExecuteOnDocumentCreated(&HSTRING::from(sid.as_str()));
                    }
                }
            }
            Ok(())
        }));
        // SAFETY: COM call on a live webview with a valid script string.
        unsafe {
            let _ = wv.AddScriptToExecuteOnDocumentCreated(&HSTRING::from(script.as_str()), &handler);
        }
    }

    /// The page's content starts loading: apply its site's rules in case the per-site script
    /// was registered too late for this document (the script does nothing the second time).
    fn on_content_loading(&self, id: u32) {
        let job = self
            .tab_ref(id, |t| {
                let host = host_of(&t.nav_uri).to_ascii_lowercase();
                t.site
                    .as_ref()
                    .filter(|s| s.host == host)
                    .map(|s| (t.webview.clone(), s.script.clone()))
            })
            .flatten();
        if let Some((Some(wv), script)) = job {
            let h = ExecuteScriptCompletedHandler::create(Box::new(|_, _| Ok(())));
            // SAFETY: COM call on a live webview with a valid script string.
            unsafe {
                let _ = wv.ExecuteScript(&HSTRING::from(script.as_str()), &h);
            }
        }
    }

    fn observe_webrtc(&self) -> Observed {
        let i = self.inner.borrow();
        if i.cfg.network.is_none() {
            return Observed::Unverifiable(
                "Not in effect: Encrypted DNS is off, so there is no network layer and WebRTC connects directly."
                    .into(),
            );
        }
        match (&i.webrtc, &i.webrtc_temp) {
            (Err(e), _) => Observed::Unverifiable(format!("UNTRACE could not set it in the engine's profile ({e}).")),
            (_, Some(Err(e))) => Observed::Unverifiable(format!("Not set for the temporary tabs ({e}).")),
            (Ok(on), Some(Ok(t))) if t != on => {
                Observed::Unverifiable("The temporary tabs use a different setting.".into())
            }
            (Ok(on), _) => Observed::Verified(Value::Bool(*on)),
        }
    }

    fn observe_cosmetic(&self) -> Observed {
        let i = self.inner.borrow();
        let live = || i.tabs.iter().filter(|t| t.webview.is_some());
        if !i.cosmetic_on {
            return if live().all(|t| t.cosmetic == CosmeticState::None) {
                Observed::Verified(Value::Bool(false))
            } else {
                Observed::Unverifiable("Open tabs still carry the hiding script.".into())
            };
        }
        let Some(rules) = i.filters.cosmetic() else {
            return Observed::Unverifiable("The block lists are not loaded yet.".into());
        };
        let lists: Vec<ListId> = i.filters.content().map(|c| c.lists().to_vec()).unwrap_or_default();
        if lists.is_empty() || rules.is_empty() {
            return Observed::Unverifiable(
                "Both the ad and the tracker list are off, so there is nothing to hide.".into(),
            );
        }
        if let Some(id) = lists.iter().find(|id| !rules.has_canary(**id)) {
            return Observed::Unverifiable(format!(
                "The hiding rules of {} are missing.",
                untrace_filter::info(*id).title
            ));
        }
        if live().any(|t| t.cosmetic == CosmeticState::None) {
            return Observed::Unverifiable("The engine did not accept the hiding script on every tab.".into());
        }
        Observed::Verified(Value::Bool(true))
    }

    /// MEASUREMENT ONLY (compat runner): turn the per-site hiding script off, to measure its
    /// share of the cost. Never called by UNTRACE itself.
    pub fn set_cosmetic_site_rules_for_measurement(&self, on: bool) {
        self.inner.borrow_mut().cosmetic_site_rules = on;
    }

    /// The network layer's start-up check (D-006, D-026).
    pub fn network_check(&self) -> NetworkCheck {
        self.inner.borrow().network_check.clone()
    }

    /// The network layer's proxy, when the engine runs through it.
    pub fn proxy(&self) -> Option<Proxy> {
        self.inner.borrow().cfg.network.clone()
    }

    /// Sites allowed to reach this computer and the local network (from Settings).
    pub fn set_local_sites(&self, sites: impl IntoIterator<Item = String>) {
        self.inner.borrow_mut().local_sites = sites.into_iter().map(|s| s.to_ascii_lowercase()).collect();
        self.changed();
    }

    /// Allow (or stop allowing) a site to reach the local network in temporary tabs, until the
    /// temporary session ends. Never saved.
    pub fn set_temp_site_local(&self, site: &str, allowed: bool) {
        {
            let mut i = self.inner.borrow_mut();
            if allowed {
                i.temp_local_sites.insert(site.to_ascii_lowercase());
            } else {
                i.temp_local_sites.remove(site);
            }
        }
        self.changed();
    }

    /// Settings read-back for a list switch: is the list loaded and matching, and is request
    /// filtering registered on every tab?
    pub fn filter_state(&self, id: ListId) -> Observed {
        let i = self.inner.borrow();
        if i.filter_registration_failed {
            return Observed::Unverifiable("the browser engine refused to let UNTRACE check requests".into());
        }
        Observed::Verified(Value::Bool(i.filters.verify(id)))
    }

    /// Sites where the user turned ads/trackers blocking off (from Settings).
    pub fn set_site_exceptions(&self, sites: impl IntoIterator<Item = String>) {
        self.inner.borrow_mut().site_exceptions = sites.into_iter().map(|s| s.to_ascii_lowercase()).collect();
        self.refresh_cosmetic();
        self.changed();
    }

    /// Would a request from this page be filtered by the ads/trackers lists? (Self-check and UI.)
    pub fn site_filtered(&self, page_url: &str) -> bool {
        let i = self.inner.borrow();
        !registrable_domain(page_url).is_some_and(|s| i.site_exceptions.contains(&s))
    }

    /// SELF-CHECK ONLY (`--self-check`): accepted downloads go to `dir` without the save dialog,
    /// so the save path can be verified end to end without clicking a native window.
    pub fn set_test_download_dir(&self, dir: PathBuf) {
        self.inner.borrow_mut().test_download_dir = Some(dir);
    }

    fn weak(&self) -> Weak<RefCell<Inner>> {
        Rc::downgrade(&self.inner)
    }

    fn changed(&self) {
        // An empty new tab hides its page view (TabInfo::new_tab_page); when the active tab
        // starts or stops being one, the page view is shown or hidden.
        let relayout = {
            let mut i = self.inner.borrow_mut();
            let active = i.active;
            let mut relayout = false;
            for t in i.tabs.iter_mut() {
                let empty = !t.from_page && is_blank_address(&t.info.url);
                if t.info.new_tab_page != empty {
                    t.info.new_tab_page = empty;
                    relayout |= Some(t.info.id) == active;
                }
            }
            relayout
        };
        if relayout {
            self.layout();
        }
        let notify = self.inner.borrow().notify.clone();
        notify(HostEvent::Changed);
    }

    fn fail(&self, message: String) {
        self.inner.borrow_mut().engine_error = Some(message);
        self.changed();
    }

    fn create_environment(&self) -> std::result::Result<(), String> {
        let cfg = self.inner.borrow().cfg.clone();
        std::fs::create_dir_all(&cfg.data_dir).map_err(|e| format!("content data folder: {e}"))?;
        // D-052: the WebRTC policy goes into the profile before the engine loads it.
        self.inner.borrow_mut().webrtc = crate::engine_files::set_webrtc_policy(
            &crate::engine_files::profile_dir(&cfg.data_dir, &cfg.profile),
            cfg.network.is_some() && cfg.webrtc_proxy_only,
        );
        let options = CoreWebView2EnvironmentOptions::default();
        // SAFETY: setters on our own option object before it is handed to the runtime.
        unsafe {
            options.set_enable_tracking_prevention(true);
            options.set_is_custom_crash_reporting_enabled(true); // D-013: dumps stay local
            options.set_are_browser_extensions_enabled(false); // D-022
            // Only the network layer's proxy flags (D-006), or none.
            options.set_additional_browser_arguments(
                cfg.network.as_ref().map(Proxy::browser_arguments).unwrap_or_default(),
            );
        }
        let options: ICoreWebView2EnvironmentOptions = options.into();
        let udf = HSTRING::from(cfg.data_dir.as_os_str());
        let weak = self.weak();
        let handler = CreateCoreWebView2EnvironmentCompletedHandler::create(Box::new(move |hr, env| {
            if let Some(h) = upgrade(&weak) {
                match (hr, env) {
                    (Ok(()), Some(env)) => h.on_environment(env),
                    (Err(e), _) => h.fail(format!("The browser engine could not start ({}).", e.message())),
                    _ => h.fail("The browser engine could not start.".into()),
                }
            }
            Ok(())
        }));
        // SAFETY: valid strings and options; completion arrives on this thread's message loop.
        unsafe { CreateCoreWebView2EnvironmentWithOptions(PCWSTR::null(), &udf, &options, &handler) }.map_err(|e| {
            format!(
                "WebView2 Runtime not available ({}). Install or repair the Microsoft Edge WebView2 Runtime.",
                e.message()
            )
        })
    }

    fn on_environment(&self, env: ICoreWebView2Environment) {
        // SAFETY: out-parameter string owned by us afterwards (`take`).
        let version = take_str(|p| unsafe { env.BrowserVersionString(p) });
        if let Some(major) = version.as_deref().and_then(runtime_major)
            && major < MIN_RUNTIME_MAJOR
        {
            self.inner.borrow_mut().runtime_version = version.clone();
            self.fail(format!(
                "The installed WebView2 Runtime ({}) is too old. UNTRACE needs version {MIN_RUNTIME_MAJOR} or newer; \
                     update it through Windows Update or from Microsoft.",
                version.unwrap_or_default()
            ));
            return;
        }
        let weak = self.weak();
        let mut tok = 0i64;
        // SAFETY: registering an event handler on a live environment.
        unsafe {
            let _ = env.add_NewBrowserVersionAvailable(
                &NewBrowserVersionAvailableEventHandler::create(Box::new(move |_, _| {
                    if let Some(h) = upgrade(&weak) {
                        h.inner.borrow_mut().update_available = true;
                        h.changed();
                    }
                    Ok(())
                })),
                &mut tok,
            );
        }
        let pending: Vec<u32> = {
            let mut i = self.inner.borrow_mut();
            i.env = Some(env);
            i.runtime_version = version;
            i.tabs
                .iter()
                .filter(|t| t.controller.is_none())
                .map(|t| t.info.id)
                .collect()
        };
        for id in pending {
            self.create_controller(id);
        }
        self.changed();
    }

    // ------------------------------------------------------------------ tabs

    pub fn new_tab(&self, url: Option<String>) -> u32 {
        self.new_tab_inner(url, None, false)
    }

    /// A temporary tab. All temporary tabs share one InPrivate profile with a random name; its
    /// cookies, storage, cache and history are discarded when the last temporary tab closes.
    pub fn new_temporary_tab(&self, url: Option<String>) -> u32 {
        self.new_tab_inner(url, None, true)
    }

    fn new_tab_inner(&self, url: Option<String>, on_ready: Option<OnReady>, temporary: bool) -> u32 {
        let (id, env_ready) = {
            let mut i = self.inner.borrow_mut();
            let id = i.next_id;
            i.next_id += 1;
            if temporary && i.temp_profile.is_none() {
                let name = random_profile_name();
                // D-052: before the engine creates this profile.
                let proxy_only = i.cfg.network.is_some() && i.cfg.webrtc_proxy_only;
                i.webrtc_temp = Some(crate::engine_files::set_webrtc_policy(
                    &crate::engine_files::profile_dir(&i.cfg.data_dir, &name),
                    proxy_only,
                ));
                i.temp_profile = Some((name, None));
            }
            let from_page = on_ready.is_some();
            i.tabs.push(Tab {
                info: TabInfo {
                    temporary,
                    new_tab_page: !from_page,
                    ..blank_info(id)
                },
                from_page,
                controller: None,
                webview: None,
                pending_url: url,
                on_ready,
                nav_uri: String::new(),
                upgrade: None,
                nav_id: 0,
                cert_error: None,
                cleaned: None,
                cancelled: Vec::new(),
                cosmetic: CosmeticState::None,
                cosmetic_gen: 0,
                site: None,
                site_gen: 0,
            });
            i.active = Some(id);
            (id, i.env.is_some())
        };
        if env_ready {
            self.create_controller(id);
        }
        self.layout();
        self.changed();
        id
    }

    fn create_controller(&self, id: u32) {
        let (env, container, profile, private) = {
            let i = self.inner.borrow();
            let Some(env) = i.env.clone() else { return };
            let temporary = i.tabs.iter().any(|t| t.info.id == id && t.info.temporary);
            let profile = match (temporary, &i.temp_profile) {
                (true, Some((name, _))) => name.clone(),
                (true, None) => return, // the temporary session ended before this tab was created
                (false, _) => i.cfg.profile.clone(),
            };
            (env, i.container, profile, temporary)
        };
        let result = (|| -> windows::core::Result<()> {
            let env10: ICoreWebView2Environment10 = env.cast()?;
            // SAFETY: COM calls on a live environment; strings outlive the calls.
            let opts = unsafe { env10.CreateCoreWebView2ControllerOptions()? };
            unsafe {
                opts.SetProfileName(&HSTRING::from(profile.as_str()))?;
                opts.SetIsInPrivateModeEnabled(private)?;
            }
            let weak = self.weak();
            let handler = CreateCoreWebView2ControllerCompletedHandler::create(Box::new(move |hr, c| {
                if let Some(h) = upgrade(&weak) {
                    match (hr, c) {
                        (Ok(()), Some(c)) => h.on_controller(id, c),
                        (Err(e), _) => h.fail(format!("A tab could not be created ({}).", e.message())),
                        _ => h.fail("A tab could not be created.".into()),
                    }
                }
                Ok(())
            }));
            // SAFETY: container is our live child window; completion arrives on this thread.
            unsafe { env10.CreateCoreWebView2ControllerWithOptions(container, &opts, &handler) }
        })();
        if let Err(e) = result {
            self.fail(format!("A tab could not be created ({}).", e.message()));
        }
    }

    fn on_controller(&self, id: u32, c: ICoreWebView2Controller) {
        // SAFETY: controller just delivered by the runtime.
        let Ok(wv) = (unsafe { c.CoreWebView2() }) else {
            self.fail("A tab could not be created.".into());
            return;
        };
        let exists = self.inner.borrow().tabs.iter().any(|t| t.info.id == id);
        if !exists {
            // Closed before it finished creating.
            // SAFETY: closing a controller we own.
            unsafe {
                let _ = c.Close();
            }
            return;
        }
        let (devtools, bg) = {
            let i = self.inner.borrow();
            (i.cfg.devtools, i.cfg.background)
        };
        if let Err(e) = configure(&c, &wv, devtools, bg) {
            self.fail(format!("A tab could not be secured ({}); it was closed.", e.message()));
            // SAFETY: closing a controller we own.
            unsafe {
                let _ = c.Close();
            }
            self.remove_tab(id);
            return;
        }
        self.wire(id, &c, &wv);
        // Keep each profile once a tab delivers it, and give a new one the configured tracking
        // prevention level (the level belongs to the profile, not the view).
        // SAFETY: COM getter on a live webview.
        let profile = unsafe { wv.cast::<ICoreWebView2_13>().and_then(|w| w.Profile()) }.ok();
        let (pending, on_ready, first, temporary, new_profile, level) = {
            let mut i = self.inner.borrow_mut();
            let level = i.tracking_level;
            let Some(temporary) = i.tabs.iter().find(|t| t.info.id == id).map(|t| t.info.temporary) else {
                return;
            };
            let new_profile = if temporary {
                match &mut i.temp_profile {
                    Some((_, slot @ None)) => {
                        *slot = profile.clone();
                        profile.clone()
                    }
                    _ => None,
                }
            } else if i.std_profile.is_none() {
                i.std_profile = profile.clone();
                profile.clone()
            } else {
                None
            };
            let first = !temporary && !i.history_clear_started;
            if first {
                i.history_clear_started = true;
            }
            let Some(t) = i.tabs.iter_mut().find(|t| t.info.id == id) else {
                return;
            };
            t.controller = Some(c);
            t.webview = Some(wv.clone());
            t.info.ready = true;
            (
                t.pending_url.take(),
                t.on_ready.take(),
                first,
                temporary,
                new_profile,
                level,
            )
        };
        if let Some(p) = &new_profile {
            let _ = set_tracking_level(p, level);
            let _ = set_color_scheme(p, self.inner.borrow().color_scheme);
        }
        if first {
            self.start_session_clear();
            self.refresh_stored_permissions();
        }
        self.claim_worker_requests();
        self.layout();
        // M6: the hiding script first, so the tab's first page is covered too.
        let proceed: AfterCosmetic = Box::new(move |h: &ContentHost| {
            match on_ready {
                Some(f) => f(&wv), // window.open: the runtime navigates the new view itself
                None => {
                    let url = pending.unwrap_or_else(|| "about:blank".into());
                    let hold = !temporary && !h.inner.borrow().startup_clear_done && url != "about:blank";
                    if hold {
                        h.inner.borrow_mut().held_navigations.push((id, url));
                    } else {
                        // SAFETY: navigating a live webview.
                        unsafe {
                            let _ = wv.Navigate(&HSTRING::from(url.as_str()));
                        }
                    }
                }
            }
            h.changed();
        });
        self.register_cosmetic(id, Some(proceed));
        self.changed();
    }

    /// The standard profile (cookies, permissions and storage that persist).
    fn profile(&self) -> Option<ICoreWebView2Profile> {
        self.inner.borrow().std_profile.clone()
    }

    /// Browsing data to remove before the first page of this session loads (set before the
    /// first tab is created).
    pub fn set_startup_clear(&self, kinds: ClearKinds) {
        self.inner.borrow_mut().startup_clear = kinds;
    }

    /// D-014: WebView2 keeps browsing history on disk (M0/S5); clear it, and whatever the previous
    /// session failed to clear on exit, before this session's first page loads.
    fn start_session_clear(&self) {
        let kinds = ClearKinds {
            history: true,
            ..self.inner.borrow().startup_clear
        };
        let weak = self.weak();
        let started = self.clear_data(kinds, move |r| {
            if let Some(host) = upgrade(&weak) {
                host.inner.borrow_mut().history_cleared = Some(r.is_ok());
                host.after_session_clear();
            }
        });
        if !started {
            self.inner.borrow_mut().history_cleared = Some(false);
            self.after_session_clear();
            return;
        }
        // Pages must never wait forever: if the engine has not answered in 10 s, they load and
        // Diagnostics reports the start-up clearing as not verified.
        let weak = self.weak();
        container::defer_after(10_000, move || {
            if let Some(host) = upgrade(&weak)
                && !host.inner.borrow().startup_clear_done
                && !host.inner.borrow().network_check_started
            {
                host.inner.borrow_mut().history_cleared = Some(false);
                host.after_session_clear();
            }
        });
    }

    /// Start-up, step 2: with the network layer on, check that the engine's requests reach the
    /// proxy with this launch's credentials before the first page loads. This also answers the
    /// proxy's one-time challenge, so no page sees it (D-026).
    fn after_session_clear(&self) {
        let Some(proxy) = self.proxy() else {
            self.inner.borrow_mut().network_check = NetworkCheck::Off;
            self.release_held_navigations();
            return;
        };
        if std::mem::replace(&mut self.inner.borrow_mut().network_check_started, true) {
            return;
        }
        let first = {
            let i = self.inner.borrow();
            i.tabs
                .iter()
                .find(|t| !t.info.temporary)
                .and_then(|t| t.webview.clone())
        };
        let Some(wv) = first else {
            self.inner.borrow_mut().network_check = NetworkCheck::Failed {
                reason: "No tab was open to make the check from.".into(),
            };
            self.release_held_navigations();
            return;
        };
        self.inner.borrow_mut().network_check = NetworkCheck::Pending;
        let name = proxy.new_probe();
        let started = std::time::Instant::now();
        send_probe(&wv, &name);
        self.poll_network_check(proxy, wv, name, started, 0);
    }

    fn poll_network_check(
        &self,
        proxy: Proxy,
        wv: ICoreWebView2,
        name: String,
        started: std::time::Instant,
        tick: u32,
    ) {
        if proxy.probe_seen(&name) {
            self.inner.borrow_mut().network_check = NetworkCheck::Passed {
                ms: started.elapsed().as_millis() as u32,
            };
            self.release_held_navigations();
            return;
        }
        let elapsed = tick * 100;
        if elapsed >= NETWORK_CHECK_MS {
            self.inner.borrow_mut().network_check = NetworkCheck::Failed {
                reason: "A test request from the engine did not reach the network layer.".into(),
            };
            self.release_held_navigations();
            return;
        }
        if matches!(elapsed, 300 | 800 | 1_500 | 3_000) {
            // The first may have been dropped by the tab's initial blank page loading.
            send_probe(&wv, &name);
        }
        let weak = self.weak();
        container::defer_after(100, move || {
            if let Some(h) = upgrade(&weak) {
                h.poll_network_check(proxy, wv, name, started, tick + 1);
            }
        });
    }

    fn release_held_navigations(&self) {
        let held = {
            let mut i = self.inner.borrow_mut();
            i.startup_clear_done = true;
            std::mem::take(&mut i.held_navigations)
        };
        for (id, url) in held {
            self.navigate_tab(id, &url);
        }
        self.changed();
    }

    /// Remove browsing data from the standard profile. `done` runs on this thread when the engine
    /// has finished. Returns false (and never calls `done`) if the request could not be made.
    pub fn clear_data(&self, kinds: ClearKinds, done: impl FnOnce(std::result::Result<(), String>) + 'static) -> bool {
        let Some(p2) = self.profile().and_then(|p| p.cast::<ICoreWebView2Profile2>().ok()) else {
            return false;
        };
        let mut done = Some(done);
        let h = ClearBrowsingDataCompletedHandler::create(Box::new(move |hr| {
            if let Some(d) = done.take() {
                d(hr.map_err(|e| e.message()));
            }
            Ok(())
        }));
        // SAFETY: COM call on a live profile; completion arrives on this thread.
        unsafe { p2.ClearBrowsingData(kinds.engine_kinds(), &h) }.is_ok()
    }

    fn remove_tab(&self, id: u32) -> Option<ICoreWebView2Controller> {
        let mut i = self.inner.borrow_mut();
        let idx = i.tabs.iter().position(|t| t.info.id == id)?;
        let tab = i.tabs.remove(idx);
        if i.active == Some(id) {
            let next = i
                .tabs
                .get(idx)
                .or_else(|| i.tabs.get(idx.wrapping_sub(1)))
                .map(|t| t.info.id);
            i.active = next;
        }
        if tab.info.temporary && !i.tabs.iter().any(|t| t.info.temporary) {
            // The temporary session ends: the engine discards an InPrivate profile's data once
            // its last view closes. The next temporary tab gets a new random profile.
            i.temp_profile = None;
            i.webrtc_temp = None;
            i.temp_site_exceptions.clear();
            i.temp_local_sites.clear();
            i.cosmetic_scripts[1] = None;
            i.temp_worker_owner = None;
        }
        tab.controller
    }

    pub fn close_tab(&self, id: u32) {
        self.deny_pending(Some(id));
        if let Some(c) = self.remove_tab(id) {
            // SAFETY: closing a controller we own (never from inside its own event — see `defer`).
            unsafe {
                let _ = c.Close();
            }
        }
        self.claim_worker_requests(); // hand worker requests to another tab if this one had them
        if self.inner.borrow().tabs.is_empty() {
            self.new_tab(None);
            let notify = self.inner.borrow().notify.clone();
            notify(HostEvent::FocusAddress);
        }
        self.layout();
        self.changed();
    }

    pub fn activate(&self, id: u32) {
        {
            let mut i = self.inner.borrow_mut();
            if !i.tabs.iter().any(|t| t.info.id == id) {
                return;
            }
            i.active = Some(id);
        }
        self.layout();
        self.changed();
    }

    pub fn cycle(&self, forward: bool) {
        let next = {
            let i = self.inner.borrow();
            let n = i.tabs.len();
            if n < 2 {
                return;
            }
            let pos = i.tabs.iter().position(|t| Some(t.info.id) == i.active).unwrap_or(0);
            let np = if forward { (pos + 1) % n } else { (pos + n - 1) % n };
            i.tabs[np].info.id
        };
        self.activate(next);
    }

    pub fn active_id(&self) -> Option<u32> {
        self.inner.borrow().active
    }

    fn tab_webview(&self, id: u32) -> Option<ICoreWebView2> {
        self.inner
            .borrow()
            .tabs
            .iter()
            .find(|t| t.info.id == id)
            .and_then(|t| t.webview.clone())
    }

    fn active_webview(&self) -> Option<ICoreWebView2> {
        let id = self.active_id()?;
        self.tab_webview(id)
    }

    fn active_controller(&self) -> Option<ICoreWebView2Controller> {
        let i = self.inner.borrow();
        let id = i.active?;
        i.tabs
            .iter()
            .find(|t| t.info.id == id)
            .and_then(|t| t.controller.clone())
    }

    fn navigate_tab(&self, id: u32, url: &str) {
        let hold = {
            let i = self.inner.borrow();
            !i.startup_clear_done
                && i.tabs
                    .iter()
                    .any(|t| t.info.id == id && !t.info.temporary && t.webview.is_some())
        };
        if hold {
            // The start-up clearing is still running; the page loads right after it.
            self.inner.borrow_mut().held_navigations.push((id, url.to_string()));
            return;
        }
        match self.tab_webview(id) {
            // SAFETY: navigating a live webview.
            Some(wv) => unsafe {
                let _ = wv.Navigate(&HSTRING::from(url));
            },
            None => {
                let mut i = self.inner.borrow_mut();
                if let Some(t) = i.tabs.iter_mut().find(|t| t.info.id == id) {
                    t.pending_url = Some(url.to_string());
                }
            }
        }
    }

    pub fn navigate_active(&self, url: &str) {
        if let Some(id) = self.active_id() {
            self.navigate_tab(id, url);
        }
    }

    pub fn back(&self) {
        if let Some(wv) = self.active_webview() {
            // SAFETY: COM call on a live webview.
            unsafe {
                let _ = wv.GoBack();
            }
        }
    }

    pub fn forward(&self) {
        if let Some(wv) = self.active_webview() {
            // SAFETY: COM call on a live webview.
            unsafe {
                let _ = wv.GoForward();
            }
        }
    }

    pub fn reload(&self) {
        let Some(id) = self.active_id() else { return };
        let retry = self
            .tab_ref(id, |t| t.info.interstitial.as_ref().map(interstitial_url))
            .flatten();
        match retry {
            Some(url) => {
                let _ = self.interstitial_action(id, "retry");
                let _ = url;
            }
            None => {
                if let Some(wv) = self.tab_webview(id) {
                    // SAFETY: COM call on a live webview.
                    unsafe {
                        let _ = wv.Reload();
                    }
                }
            }
        }
    }

    pub fn stop(&self) {
        if let Some(wv) = self.active_webview() {
            // SAFETY: COM call on a live webview.
            unsafe {
                let _ = wv.Stop();
            }
        }
    }

    pub fn focus_active(&self) {
        if let Some(c) = self.active_controller() {
            // SAFETY: COM call on a live controller.
            unsafe {
                let _ = c.MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
            }
        }
    }

    // ---------------------------------------------------------- interstitials

    fn set_interstitial(&self, id: u32, inter: Interstitial) {
        self.update(id, |t| {
            t.loading = false;
            // Show the address that failed (the engine never committed it).
            t.url = interstitial_url(&inter);
            t.interstitial = Some(inter);
        });
        self.layout();
        if self.active_id() == Some(id) {
            // The page view is now hidden; without this, keystrokes would go to it.
            let notify = self.inner.borrow().notify.clone();
            notify(HostEvent::FocusPanel);
        }
    }

    /// Act on UNTRACE's own error panel: "back", "retry" or "continue_http".
    pub fn interstitial_action(&self, id: u32, action: &str) -> std::result::Result<(), String> {
        let (inter, can_back) = self
            .tab_ref(id, |t| (t.info.interstitial.clone(), t.info.can_go_back))
            .ok_or("no such tab")?;
        let inter = inter.ok_or("nothing to act on")?;
        let target = match (action, &inter) {
            ("back", _) => None,
            ("retry", i) => Some(interstitial_url(i)),
            ("continue_http", Interstitial::HttpsUnavailable { http_url, host, .. }) => {
                self.inner
                    .borrow_mut()
                    .https
                    .session_exceptions
                    .insert(host.to_ascii_lowercase());
                Some(http_url.clone())
            }
            // D-033: the user's informed choice, for this host and this session only.
            ("continue_threat", Interstitial::Threat { url, host, .. }) => {
                if let Some(p) = self.proxy() {
                    p.allow_threat_host(host); // the network backstop follows the same choice
                }
                self.inner
                    .borrow_mut()
                    .threat_exceptions
                    .insert(host.to_ascii_lowercase());
                Some(url.clone())
            }
            _ => return Err("that action is not available here".into()),
        };
        self.with_tab(id, |t| {
            t.info.interstitial = None;
            t.upgrade = None;
        });
        match target {
            Some(url) => self.navigate_tab(id, &url),
            None => match self.tab_webview(id) {
                // SAFETY: COM calls on a live webview.
                Some(wv) if can_back => unsafe {
                    let _ = wv.GoBack();
                },
                Some(wv) => unsafe {
                    let _ = wv.Navigate(w!("about:blank"));
                },
                None => {}
            },
        }
        self.layout();
        self.changed();
        Ok(())
    }

    pub fn dismiss_notice(&self, id: u32) {
        self.update(id, |t| t.notice = None);
    }

    // --------------------------------------------------------------- prompts

    fn add_prompt(
        &self,
        tab: u32,
        origin: String,
        detail: PromptDetail,
        deferral: ICoreWebView2Deferral,
        args: PendingArgs,
    ) {
        let id = {
            let mut i = self.inner.borrow_mut();
            let id = i.next_prompt;
            i.next_prompt += 1;
            i.pending.push(Pending {
                id,
                tab,
                deferral,
                args,
            });
            id
        };
        self.update(tab, |t| t.prompts.push(PromptInfo { id, origin, detail }));
    }

    fn prompts_open(&self, tab: u32) -> usize {
        self.inner.borrow().pending.iter().filter(|p| p.tab == tab).count()
    }

    /// Answer a prompt. `remember` applies to permissions only (saved in the profile).
    pub fn respond(&self, prompt_id: u32, allow: bool, remember: bool) -> std::result::Result<(), String> {
        let pending = {
            let mut i = self.inner.borrow_mut();
            let pos = i
                .pending
                .iter()
                .position(|p| p.id == prompt_id)
                .ok_or("this question has expired")?;
            i.pending.remove(pos)
        };
        self.with_tab(pending.tab, |t| t.info.prompts.retain(|p| p.id != prompt_id));
        let tab = pending.tab;
        match pending.args {
            PendingArgs::Permission(a) => {
                // SAFETY: setters on live event args, then completing their deferral.
                unsafe {
                    let _ = a.SetState(if allow {
                        COREWEBVIEW2_PERMISSION_STATE_ALLOW
                    } else {
                        COREWEBVIEW2_PERMISSION_STATE_DENY
                    });
                    if let Ok(a3) = a.cast::<ICoreWebView2PermissionRequestedEventArgs3>() {
                        let _ = a3.SetSavesInProfile(remember);
                    }
                    let _ = pending.deferral.Complete();
                }
                if !allow {
                    self.update(tab, |t| t.blocked.permissions += 1);
                }
                if remember {
                    self.refresh_stored_permissions();
                }
            }
            PendingArgs::External(a) => {
                // SAFETY: setter on live event args, then completing their deferral.
                unsafe {
                    if !allow {
                        let _ = a.SetCancel(true);
                    }
                    let _ = pending.deferral.Complete();
                }
                if !allow {
                    self.update(tab, |t| t.blocked.external_apps += 1);
                }
            }
            PendingArgs::Download { args, suggested, risk } => {
                if !allow {
                    // SAFETY: setter on live event args, then completing their deferral.
                    unsafe {
                        let _ = args.SetCancel(true);
                        let _ = pending.deferral.Complete();
                    }
                } else {
                    // The save dialog is modal; run it outside the IPC command that answered.
                    let h = self.clone();
                    let deferral = pending.deferral;
                    defer(move || h.save_download(args, deferral, suggested, risk));
                }
            }
        }
        self.changed();
        Ok(())
    }

    /// Refuse every open question (of one tab, or all).
    fn deny_pending(&self, tab: Option<u32>) {
        let ids: Vec<u32> = self
            .inner
            .borrow()
            .pending
            .iter()
            .filter(|p| tab.is_none_or(|t| p.tab == t))
            .map(|p| p.id)
            .collect();
        for id in ids {
            let _ = self.respond(id, false, false);
        }
    }

    // ------------------------------------------------------------- downloads

    fn save_download(
        &self,
        args: ICoreWebView2DownloadStartingEventArgs,
        deferral: ICoreWebView2Deferral,
        suggested: PathBuf,
        risk: DownloadRisk,
    ) {
        let (owner, test_dir) = {
            let i = self.inner.borrow();
            (i.parent, i.test_download_dir.clone())
        };
        let chosen = match test_dir {
            Some(dir) => suggested.file_name().map(|n| dir.join(n)),
            None => dialog::save_as(owner, &suggested),
        };
        // SAFETY: setters on live event args, then completing their deferral.
        unsafe {
            match &chosen {
                Some(path) => {
                    let _ = args.SetResultFilePath(&HSTRING::from(path.as_os_str()));
                }
                None => {
                    let _ = args.SetCancel(true);
                }
            }
            let op = args.DownloadOperation().ok();
            let _ = deferral.Complete();
            if let (Some(path), Some(op)) = (chosen, op) {
                self.track_download(op, path, risk);
            }
        }
        self.changed();
    }

    fn track_download(&self, op: ICoreWebView2DownloadOperation, path: PathBuf, risk: DownloadRisk) {
        let mut total = 0i64;
        // SAFETY: COM getter on a live download operation.
        unsafe {
            let _ = op.TotalBytesToReceive(&mut total);
        }
        let id = {
            let mut i = self.inner.borrow_mut();
            let id = i.next_download;
            i.next_download += 1;
            let info = DownloadInfo {
                id,
                file_name: path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
                path: path.display().to_string(),
                state: "in_progress".into(),
                received: 0,
                total: (total > 0).then_some(total),
                risk,
            };
            i.downloads.push((info, Some(op.clone())));
            id
        };
        let mut tok = 0i64;
        let (w1, w2) = (self.weak(), self.weak());
        // SAFETY: registering handlers on a live download operation.
        unsafe {
            let _ = op.add_BytesReceivedChanged(
                &BytesReceivedChangedEventHandler::create(Box::new(move |s, _| {
                    if let (Some(h), Some(s)) = (upgrade(&w1), s) {
                        let mut got = 0i64;
                        let _ = s.BytesReceived(&mut got);
                        h.update_download(id, |d| d.received = got);
                    }
                    Ok(())
                })),
                &mut tok,
            );
            let _ = op.add_StateChanged(
                &StateChangedEventHandler::create(Box::new(move |s, _| {
                    if let (Some(h), Some(s)) = (upgrade(&w2), s) {
                        let mut st = COREWEBVIEW2_DOWNLOAD_STATE(0);
                        let _ = s.State(&mut st);
                        let state = match st {
                            COREWEBVIEW2_DOWNLOAD_STATE_COMPLETED => "completed",
                            COREWEBVIEW2_DOWNLOAD_STATE_INTERRUPTED => "interrupted",
                            _ => "in_progress",
                        };
                        h.update_download(id, |d| d.state = state.into());
                    }
                    Ok(())
                })),
                &mut tok,
            );
        }
        self.changed();
    }

    fn update_download(&self, id: u32, f: impl FnOnce(&mut DownloadInfo)) {
        {
            let mut i = self.inner.borrow_mut();
            let Some((d, op)) = i.downloads.iter_mut().find(|(d, _)| d.id == id) else {
                return;
            };
            f(d);
            if d.state != "in_progress" {
                *op = None;
            }
        }
        self.changed();
    }

    pub fn cancel_download(&self, id: u32) {
        let op = self
            .inner
            .borrow()
            .downloads
            .iter()
            .find(|(d, _)| d.id == id)
            .and_then(|(_, op)| op.clone());
        if let Some(op) = op {
            // SAFETY: COM call on a live download operation.
            unsafe {
                let _ = op.Cancel();
            }
        }
    }

    pub fn show_download(&self, id: u32) -> std::result::Result<(), String> {
        let path = self
            .inner
            .borrow()
            .downloads
            .iter()
            .find(|(d, _)| d.id == id)
            .map(|(d, _)| PathBuf::from(&d.path))
            .ok_or("no such download")?;
        dialog::show_in_folder(&path).map_err(|e| e.to_string())
    }

    /// Forget finished downloads (the files stay where they were saved).
    pub fn clear_downloads(&self) {
        self.inner
            .borrow_mut()
            .downloads
            .retain(|(d, _)| d.state == "in_progress");
        self.changed();
    }

    // ----------------------------------------------------- stored permissions

    fn refresh_stored_permissions(&self) {
        let Some(p4) = self.profile().and_then(|p| p.cast::<ICoreWebView2Profile4>().ok()) else {
            return;
        };
        let weak = self.weak();
        let h = GetNonDefaultPermissionSettingsCompletedHandler::create(Box::new(move |hr, list| {
            let mut out = Vec::new();
            if let (Ok(()), Some(list)) = (hr, list) {
                let mut n = 0u32;
                // SAFETY: reading a live collection returned by the runtime.
                unsafe {
                    let _ = list.Count(&mut n);
                    for i in 0..n {
                        let Ok(s) = list.GetValueAtIndex(i) else { continue };
                        let (mut kind, mut state) = (COREWEBVIEW2_PERMISSION_KIND(0), COREWEBVIEW2_PERMISSION_STATE(0));
                        let _ = s.PermissionKind(&mut kind);
                        let _ = s.PermissionState(&mut state);
                        // The engine reports "https://site/"; normalise to the origin form the
                        // UI and every other part of UNTRACE use ("https://site").
                        let raw = take_str(|p| s.PermissionOrigin(p)).unwrap_or_default();
                        let origin = url::Url::parse(&raw)
                            .map(|u| u.origin().ascii_serialization())
                            .unwrap_or(raw);
                        let permission = permission_from(kind.0);
                        out.push(StoredPermission {
                            origin,
                            permission,
                            label: permission.label().into(),
                            state: if state == COREWEBVIEW2_PERMISSION_STATE_ALLOW {
                                "allow"
                            } else {
                                "deny"
                            }
                            .into(),
                        });
                    }
                }
            }
            if let Some(host) = upgrade(&weak) {
                host.inner.borrow_mut().stored_permissions = out;
                host.changed();
            }
            Ok(())
        }));
        // SAFETY: COM call on a live profile.
        unsafe {
            let _ = p4.GetNonDefaultPermissionSettings(&h);
        }
    }

    /// Forget a saved permission decision for a site.
    pub fn reset_permission(&self, origin: &str, permission: Permission) -> std::result::Result<(), String> {
        let p4 = self
            .profile()
            .and_then(|p| p.cast::<ICoreWebView2Profile4>().ok())
            .ok_or("the browser engine is not ready")?;
        let weak = self.weak();
        let h = SetPermissionStateCompletedHandler::create(Box::new(move |_| {
            if let Some(host) = upgrade(&weak) {
                host.refresh_stored_permissions();
            }
            Ok(())
        }));
        // SAFETY: COM call on a live profile with a valid origin string.
        unsafe {
            p4.SetPermissionState(
                permission_kind(permission),
                &HSTRING::from(origin),
                COREWEBVIEW2_PERMISSION_STATE_DEFAULT,
                &h,
            )
        }
        .map_err(|e| e.message())
    }

    // ---------------------------------------------------------------- layout

    /// Place the content area (physical pixels, parent client coordinates). Hidden when `visible` is false.
    pub fn set_bounds(&self, rect: RECT, visible: bool) {
        {
            let mut i = self.inner.borrow_mut();
            i.rect = rect;
            i.visible = visible;
        }
        self.layout();
    }

    fn layout(&self) {
        let (container, rect, show_page, ctrls) = {
            let i = self.inner.borrow();
            let active_blocked = i
                .tabs
                .iter()
                .find(|t| Some(t.info.id) == i.active)
                .map(|t| t.info.interstitial.is_some() || t.info.new_tab_page)
                .unwrap_or(false);
            let ctrls: Vec<(ICoreWebView2Controller, bool)> = i
                .tabs
                .iter()
                .filter_map(|t| t.controller.clone().map(|c| (c, Some(t.info.id) == i.active)))
                .collect();
            // While UNTRACE's own panel or an empty new tab is shown, the page view and its
            // container are hidden so the UI can draw in that area (D-021: the UI never draws
            // over web content).
            (i.container, i.rect, i.visible && !active_blocked, ctrls)
        };
        let (w, h) = ((rect.right - rect.left).max(1), (rect.bottom - rect.top).max(1));
        // SAFETY: positioning our own child window and live controllers.
        unsafe {
            let flags = SWP_NOACTIVATE | if show_page { SWP_SHOWWINDOW } else { SWP_HIDEWINDOW };
            let _ = SetWindowPos(container, Some(HWND_TOP), rect.left, rect.top, w, h, flags);
            for (c, active) in ctrls {
                let _ = c.SetBounds(RECT {
                    left: 0,
                    top: 0,
                    right: w,
                    bottom: h,
                });
                let _ = c.SetIsVisible(show_page && active);
            }
        }
    }

    /// D-053: tell pages in every profile (now and as profiles appear) this colour scheme.
    pub fn set_page_color_scheme(&self, scheme: PageColorScheme) -> std::result::Result<(), String> {
        let profiles: Vec<ICoreWebView2Profile> = {
            let mut i = self.inner.borrow_mut();
            i.color_scheme = scheme;
            i.std_profile
                .iter()
                .cloned()
                .chain(i.temp_profile.as_ref().and_then(|p| p.1.clone()))
                .collect()
        };
        for p in profiles {
            set_color_scheme(&p, scheme).map_err(|e| e.message())?;
        }
        Ok(())
    }

    /// The colour scheme read back from every live profile; `None` before a profile exists,
    /// `Err` if they disagree or cannot be read.
    pub fn page_color_scheme(&self) -> Option<std::result::Result<PageColorScheme, String>> {
        let profiles: Vec<ICoreWebView2Profile> = {
            let i = self.inner.borrow();
            i.std_profile
                .iter()
                .cloned()
                .chain(i.temp_profile.as_ref().and_then(|p| p.1.clone()))
                .collect()
        };
        if profiles.is_empty() {
            return None;
        }
        let read: Vec<Option<PageColorScheme>> = profiles.iter().map(read_color_scheme).collect();
        Some(match read.as_slice() {
            [Some(first), rest @ ..] if rest.iter().all(|r| r == &Some(*first)) => Ok(*first),
            _ if read.iter().any(Option::is_none) => Err("the engine did not report it".into()),
            _ => Err("the temporary tabs report a different scheme".into()),
        })
    }

    pub fn set_background(&self, rgb: [u8; 3]) {
        let ctrls: Vec<ICoreWebView2Controller> = {
            let mut i = self.inner.borrow_mut();
            i.cfg.background = rgb;
            i.tabs.iter().filter_map(|t| t.controller.clone()).collect()
        };
        for c in ctrls {
            let _ = set_background(&c, rgb);
        }
    }

    // -------------------------------------------------------------- snapshot

    pub fn snapshot(&self) -> Snapshot {
        let i = self.inner.borrow();
        let mut site_exceptions: Vec<String> = i.site_exceptions.iter().cloned().collect();
        site_exceptions.sort();
        let mut temp_site_exceptions: Vec<String> = i.temp_site_exceptions.iter().cloned().collect();
        temp_site_exceptions.sort();
        let mut local_network_sites: Vec<String> = i.local_sites.iter().cloned().collect();
        local_network_sites.sort();
        let mut temp_local_network_sites: Vec<String> = i.temp_local_sites.iter().cloned().collect();
        temp_local_network_sites.sort();
        Snapshot {
            temp_site_exceptions,
            local_network_sites,
            temp_local_network_sites,
            tabs: i
                .tabs
                .iter()
                .map(|t| TabInfo {
                    site: registrable_domain(&t.info.url),
                    ..t.info.clone()
                })
                .collect(),
            site_exceptions,
            active: i.active,
            runtime_version: i.runtime_version.clone(),
            engine_error: i.engine_error.clone(),
            engine_update_available: i.update_available,
            downloads: i.downloads.iter().map(|(d, _)| d.clone()).collect(),
            stored_permissions: i.stored_permissions.clone(),
        }
    }

    pub fn engine_info(&self) -> EngineInfo {
        let (env, cfg, version, error, first, cleared, n, shared, https_on, exceptions, update) = {
            let i = self.inner.borrow();
            let first = i.tabs.iter().find_map(|t| t.webview.clone());
            (
                i.env.clone(),
                i.cfg.clone(),
                i.runtime_version.clone(),
                i.engine_error.clone(),
                first,
                i.history_cleared,
                i.tabs.len(),
                i.shared_env,
                i.https.enabled,
                i.https.session_exceptions.len(),
                i.update_available,
            )
        };
        let mut info = EngineInfo {
            runtime_version: version,
            minimum_runtime_major: MIN_RUNTIME_MAJOR,
            engine_error: error,
            update_available: update,
            profile: cfg.profile.clone(),
            data_dir: if shared {
                "shared with the UI view (Tauri)".into()
            } else {
                cfg.data_dir.display().to_string()
            },
            // Both environments keep WebView2's default (on); neither UNTRACE nor Tauri turns it off.
            tracking_prevention_enabled: true,
            // Dedicated: UNTRACE enables custom crash reporting. Shared: Tauri/wry 0.57 never sets it.
            crash_reports_local: Some(!shared),
            shared_environment: shared,
            browser_arguments: if shared {
                "set by Tauri: --disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection".into()
            } else {
                String::new()
            },
            history_cleared_at_start: cleared,
            https_only: https_on,
            https_session_exceptions: exceptions,
            open_tabs: n,
            ..Default::default()
        };
        {
            let i = self.inner.borrow();
            info.request_filtering_registered = !i.filter_registration_failed && !i.tabs.is_empty();
            info.worker_requests_tab = i.worker_owner;
            info.worker_requests_blocked = i.worker_blocked;
            info.threat_session_exceptions = i.threat_exceptions.len();
        }
        if let Some(env) = env
            && let Ok(e11) = env.cast::<ICoreWebView2Environment11>()
        {
            // SAFETY: out-parameter string, freed by `take`.
            info.crash_report_folder = take_str(|p| unsafe { e11.FailureReportFolderPath(p) });
        }
        if let Some(wv) = first {
            // SAFETY: read-only COM getters on a live webview.
            unsafe {
                if let Ok(s) = wv.Settings() {
                    let mut b = BOOL(0);
                    if s.IsWebMessageEnabled(&mut b).is_ok() {
                        info.web_messages_enabled = Some(b.as_bool());
                    }
                    if s.AreHostObjectsAllowed(&mut b).is_ok() {
                        info.host_objects_allowed = Some(b.as_bool());
                    }
                    if s.IsBuiltInErrorPageEnabled(&mut b).is_ok() {
                        info.builtin_error_pages_enabled = Some(b.as_bool());
                    }
                    if let Ok(s4) = s.cast::<ICoreWebView2Settings4>() {
                        if s4.IsPasswordAutosaveEnabled(&mut b).is_ok() {
                            info.password_autosave_enabled = Some(b.as_bool());
                        }
                        if s4.IsGeneralAutofillEnabled(&mut b).is_ok() {
                            info.autofill_enabled = Some(b.as_bool());
                        }
                    }
                    if let Ok(s8) = s.cast::<ICoreWebView2Settings8>()
                        && s8.IsReputationCheckingRequired(&mut b).is_ok()
                    {
                        info.smartscreen_enabled = Some(b.as_bool());
                    }
                }
            }
        }
        let (std_profile, temp_profile, temporary_tabs, strip) = {
            let i = self.inner.borrow();
            (
                i.std_profile.clone(),
                i.temp_profile.as_ref().and_then(|p| p.1.clone()),
                i.tabs.iter().filter(|t| t.info.temporary).count(),
                i.strip_params,
            )
        };
        let level_name = |p: &ICoreWebView2Profile| {
            read_tracking_level(p).map(|l| {
                TRACKING_LEVELS
                    .get(l as usize)
                    .copied()
                    .unwrap_or("unknown")
                    .to_string()
            })
        };
        info.tracking_prevention_level = std_profile.as_ref().and_then(level_name);
        info.temp_tracking_prevention_level = temp_profile.as_ref().and_then(level_name);
        info.temporary_tabs = temporary_tabs;
        info.strip_tracking_params = strip;
        {
            let i = self.inner.borrow();
            if let Some(p) = &i.cfg.network {
                info.network_layer = true;
                info.browser_arguments = p.browser_arguments();
            }
            info.network_check = Some(i.network_check.clone());
            info.local_network_protection = i.local_protect;
            info.webrtc_proxy_only = i.cfg.network.as_ref().map(|_| i.webrtc.clone());
            info.local_network_worker_blocked = i.local_worker_blocked;
            info.hide_elements = i.cosmetic_on;
            info.hide_elements_tabs = i.tabs.iter().filter(|t| t.cosmetic != CosmeticState::None).count();
            info.hide_elements_script_bytes = i.cosmetic_scripts[0].as_ref().map_or(0, |s| s.len());
            info.cosmetic_rules = i.filters.cosmetic().map(|r| r.stats.clone());
        }
        info
    }

    // ------------------------------------------------------ privacy controls

    fn set_tracking_prevention(&self, level: &str) -> std::result::Result<(), String> {
        let l = TRACKING_LEVELS
            .iter()
            .position(|x| *x == level)
            .ok_or("unknown tracking prevention level")? as i32;
        let profiles: Vec<ICoreWebView2Profile> = {
            let mut i = self.inner.borrow_mut();
            i.tracking_level = l;
            i.std_profile
                .iter()
                .cloned()
                .chain(i.temp_profile.as_ref().and_then(|p| p.1.clone()))
                .collect()
        };
        for p in profiles {
            set_tracking_level(&p, l).map_err(|e| e.message())?;
        }
        Ok(())
    }

    /// Read back the level from every live profile; they must agree with each other.
    fn observe_tracking_prevention(&self) -> Observed {
        let profiles: Vec<ICoreWebView2Profile> = {
            let i = self.inner.borrow();
            i.std_profile
                .iter()
                .cloned()
                .chain(i.temp_profile.as_ref().and_then(|p| p.1.clone()))
                .collect()
        };
        if profiles.is_empty() {
            return Observed::Unverifiable("No tab is open yet to read the setting from.".into());
        }
        let mut seen = None;
        for p in profiles {
            let Some(l) = read_tracking_level(&p) else {
                return Observed::Unverifiable("The engine did not report the level.".into());
            };
            match seen {
                None => seen = Some(l),
                Some(s) if s != l => {
                    return Observed::Unverifiable("Normal and temporary tabs report different levels.".into());
                }
                _ => {}
            }
        }
        match seen.and_then(|l| TRACKING_LEVELS.get(l as usize)) {
            Some(name) => Observed::Verified(Value::Choice((*name).into())),
            None => Observed::Unverifiable("The engine reported an unknown level.".into()),
        }
    }

    /// Turn ads/trackers blocking off (or on) for a site in temporary tabs only, until the
    /// temporary session ends. Never saved.
    pub fn set_temp_site_filtering(&self, site: &str, on: bool) {
        {
            let mut i = self.inner.borrow_mut();
            if on {
                i.temp_site_exceptions.remove(site);
            } else {
                i.temp_site_exceptions.insert(site.to_ascii_lowercase());
            }
        }
        self.refresh_cosmetic();
        self.changed();
    }

    /// Sites with cookies in the standard profile, from the engine's cookie store.
    pub fn cookie_sites(&self, done: impl FnOnce(std::result::Result<Vec<CookieSite>, String>) + 'static) {
        self.read_cookies(move |r| {
            done(r.map(|cookies| {
                let mut by: BTreeMap<String, (u32, Vec<String>)> = BTreeMap::new();
                for (domain, _) in cookies {
                    let host = domain.trim_start_matches('.').to_ascii_lowercase();
                    let site = registrable_domain(&format!("https://{host}/")).unwrap_or_else(|| host.clone());
                    let e = by.entry(site).or_default();
                    e.0 += 1;
                    if !e.1.contains(&host) {
                        e.1.push(host);
                    }
                }
                by.into_iter()
                    .map(|(site, (cookies, mut hosts))| {
                        hosts.sort();
                        CookieSite { site, cookies, hosts }
                    })
                    .collect()
            }))
        });
    }

    /// All cookies of the standard profile as (domain, cookie).
    fn read_cookies(
        &self,
        done: impl FnOnce(std::result::Result<Vec<(String, ICoreWebView2Cookie)>, String>) + 'static,
    ) {
        let Some(cm) = self
            .profile()
            .and_then(|p| p.cast::<ICoreWebView2Profile5>().ok())
            // SAFETY: COM getter on a live profile.
            .and_then(|p| unsafe { p.CookieManager() }.ok())
        else {
            done(Err("No normal tab is open yet; open one to see cookies.".into()));
            return;
        };
        // Shared so that a refused call can still report back (the handler then never runs).
        let slot = Rc::new(RefCell::new(Some(done)));
        let in_handler = slot.clone();
        let h = GetCookiesCompletedHandler::create(Box::new(move |hr, list| {
            let Some(d) = in_handler.borrow_mut().take() else {
                return Ok(());
            };
            match (hr, list) {
                (Ok(()), Some(list)) => {
                    let mut out = Vec::new();
                    let mut n = 0u32;
                    // SAFETY: reading a live collection returned by the runtime.
                    unsafe {
                        let _ = list.Count(&mut n);
                        for k in 0..n {
                            if let Ok(c) = list.GetValueAtIndex(k)
                                && let Some(domain) = take_str(|p| c.Domain(p))
                            {
                                out.push((domain, c));
                            }
                        }
                    }
                    d(Ok(out));
                }
                (Err(e), _) => d(Err(e.message())),
                _ => d(Err("The engine returned no cookie list.".into())),
            }
            Ok(())
        }));
        // SAFETY: COM call on a live cookie manager; an empty URI lists every cookie.
        if let Err(e) = unsafe { cm.GetCookies(w!(""), &h) } {
            let pending = slot.borrow_mut().take();
            if let Some(d) = pending {
                d(Err(e.message()));
            }
        }
    }

    /// Delete a site's cookies and stored data (local storage, IndexedDB, cache storage, service
    /// workers) from the standard profile. Storage is removed for every host under the site that
    /// has cookies, the site itself, `www.`, and pages of the site open in normal tabs. `done`
    /// receives the number of the site's cookies still present afterwards (read back).
    pub fn delete_site_data(&self, site: &str, done: impl FnOnce(std::result::Result<u32, String>) + 'static) {
        let site = site.to_ascii_lowercase();
        let (cm, wv) = {
            let i = self.inner.borrow();
            let cm = i
                .std_profile
                .as_ref()
                .and_then(|p| p.cast::<ICoreWebView2Profile5>().ok())
                // SAFETY: COM getter on a live profile.
                .and_then(|p| unsafe { p.CookieManager() }.ok());
            let wv = i
                .tabs
                .iter()
                .filter(|t| !t.info.temporary)
                .find_map(|t| t.webview.clone());
            (cm, wv)
        };
        let Some(cm) = cm else {
            done(Err("No normal tab is open yet.".into()));
            return;
        };
        let mut hosts: HashSet<String> = [site.clone(), format!("www.{site}")].into();
        for t in self.inner.borrow().tabs.iter().filter(|t| !t.info.temporary) {
            if registrable_domain(&t.info.url).as_deref() == Some(site.as_str()) {
                hosts.insert(host_of(&t.info.url));
            }
        }
        let weak = self.weak();
        self.read_cookies(move |r| {
            let cookies = match r {
                Ok(c) => c,
                Err(e) => return done(Err(e)),
            };
            for (domain, c) in &cookies {
                let host = domain.trim_start_matches('.').to_ascii_lowercase();
                if registrable_domain(&format!("https://{host}/")).as_deref() == Some(site.as_str()) {
                    hosts.insert(host);
                    // SAFETY: COM call on a live cookie manager with a cookie it returned.
                    unsafe {
                        let _ = cm.DeleteCookie(c);
                    }
                }
            }
            if let Some(wv) = &wv {
                for h in &hosts {
                    for scheme in ["https", "http"] {
                        let params = serde_json::json!({ "origin": format!("{scheme}://{h}"), "storageTypes": "all" });
                        // SAFETY: COM call on a live webview (host-side DevTools channel).
                        unsafe {
                            let _ = wv.CallDevToolsProtocolMethod(
                                w!("Storage.clearDataForOrigin"),
                                &HSTRING::from(params.to_string()),
                                &CallDevToolsProtocolMethodCompletedHandler::create(Box::new(|_, _| Ok(()))),
                            );
                        }
                    }
                }
            }
            // Read back: count what is left of the site's cookies.
            let Some(host) = upgrade(&weak) else { return };
            host.read_cookies(move |r| {
                done(r.map(|left| {
                    left.iter()
                        .filter(|(d, _)| {
                            let h = d.trim_start_matches('.').to_ascii_lowercase();
                            registrable_domain(&format!("https://{h}/")).as_deref() == Some(site.as_str())
                        })
                        .count() as u32
                }))
            });
        });
    }

    // ------------------------------------------------- protections (Applier)

    fn set_devtools(&self, on: bool) -> std::result::Result<(), String> {
        let views: Vec<ICoreWebView2> = {
            let mut i = self.inner.borrow_mut();
            i.cfg.devtools = on;
            i.tabs.iter().filter_map(|t| t.webview.clone()).collect()
        };
        for wv in views {
            // SAFETY: COM setter on a live webview.
            unsafe { wv.Settings().and_then(|s| s.SetAreDevToolsEnabled(on)) }.map_err(|e| e.message())?;
        }
        Ok(())
    }

    fn observe_devtools(&self) -> Observed {
        let views: Vec<ICoreWebView2> = self
            .inner
            .borrow()
            .tabs
            .iter()
            .filter_map(|t| t.webview.clone())
            .collect();
        if views.is_empty() {
            return Observed::Unverifiable("No tab is open yet to read the setting from.".into());
        }
        let mut seen = None;
        for wv in views {
            let mut b = BOOL(0);
            // SAFETY: COM getter on a live webview.
            if unsafe { wv.Settings().and_then(|s| s.AreDevToolsEnabled(&mut b)) }.is_err() {
                return Observed::Unverifiable("The engine did not report the setting.".into());
            }
            match seen {
                None => seen = Some(b.as_bool()),
                Some(v) if v != b.as_bool() => return Observed::Unverifiable("Open tabs disagree.".into()),
                _ => {}
            }
        }
        Observed::Verified(Value::Bool(seen.unwrap_or(false)))
    }

    // ------------------------------------------------- self-check support

    /// Serve a local folder at `https://<host>/` (self-check only; the tab must be ready).
    ///
    /// UNTRACE's request handler answers these requests itself, before anything reaches the
    /// network. WebView2's own virtual-host mapping is not used: from runtime 158, behind an
    /// authenticated proxy, it first sends the navigation through the proxy, reports it failed
    /// and then loads it again, which UNTRACE's error page would take over (2026-11-24 probe,
    /// `spikes/harness m8 vhost`).
    pub fn map_folder(&self, tab: u32, host: &str, folder: &Path) -> std::result::Result<(), String> {
        self.tab_webview(tab).ok_or("tab not ready")?;
        self.inner
            .borrow_mut()
            .served
            .insert(host.to_ascii_lowercase(), folder.to_path_buf());
        Ok(())
    }

    /// Answer a request for a served host from its folder (200, or 404). False if the host is
    /// not served or the engine refused the response.
    fn serve_from_folder(&self, uri: &str, a: &ICoreWebView2WebResourceRequestedEventArgs) -> bool {
        let Ok(u) = url::Url::parse(uri) else { return false };
        let (folder, env) = {
            let i = self.inner.borrow();
            let Some(folder) = u
                .host_str()
                .and_then(|h| i.served.get(&h.to_ascii_lowercase()))
                .cloned()
            else {
                return false;
            };
            let Some(env) = i.env.clone() else { return false };
            (folder, env)
        };
        let segments: Vec<String> = u
            .path_segments()
            .map(|s| s.map(|x| x.to_string()).collect())
            .unwrap_or_default();
        let safe = segments
            .iter()
            .all(|s| !s.is_empty() && s != "." && s != ".." && !s.contains(['\\', ':', '%']));
        let file = segments.iter().fold(folder, |p, s| p.join(s));
        let body = if safe { std::fs::read(&file).ok() } else { None };
        let ext = file
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let ctype = match ext.as_str() {
            "html" | "htm" => "text/html; charset=utf-8",
            "js" => "text/javascript",
            "css" => "text/css",
            "json" => "application/json",
            "png" => "image/png",
            "svg" => "image/svg+xml",
            "txt" => "text/plain; charset=utf-8",
            _ => "application/octet-stream",
        };
        let (status, reason, headers, bytes) = match body {
            Some(b) => (
                200,
                "OK",
                format!("Content-Type: {ctype}\r\nCache-Control: no-store"),
                b,
            ),
            None => (404, "Not Found", "Cache-Control: no-store".to_string(), Vec::new()),
        };
        // SAFETY: a memory stream and a response object handed to live event args.
        unsafe {
            let stream = windows::Win32::UI::Shell::SHCreateMemStream(Some(&bytes));
            match env.CreateWebResourceResponse(
                stream.as_ref(),
                status,
                &HSTRING::from(reason),
                &HSTRING::from(headers),
            ) {
                Ok(resp) => a.SetResponse(&resp).is_ok(),
                Err(_) => false,
            }
        }
    }

    /// Run a script in a tab; `done` receives the JSON result (or an `ERR` string).
    pub fn execute(&self, tab: u32, js: &str, done: impl FnOnce(String) + 'static) {
        let Some(wv) = self.tab_webview(tab) else {
            done("\"ERR tab not ready\"".into());
            return;
        };
        let mut done = Some(done);
        let h = ExecuteScriptCompletedHandler::create(Box::new(move |hr, json| {
            if let Some(d) = done.take() {
                d(if hr.is_ok() {
                    json
                } else {
                    "\"ERR script failed\"".into()
                });
            }
            Ok(())
        }));
        // SAFETY: COM call with a valid script string.
        unsafe {
            let _ = wv.ExecuteScript(&HSTRING::from(js), &h);
        }
    }

    pub fn container(&self) -> HWND {
        self.inner.borrow().container
    }

    /// Close every content view and release every WebView2 object (application exit).
    ///
    /// Must run while the process is intact (window destroyed, event loop still alive). A
    /// WebView2 object released later, from thread-local teardown inside `ExitProcess`, waits
    /// for engine threads Windows has already stopped, and the process never exits.
    pub fn shutdown(&self) {
        self.deny_pending(None);
        let (tabs, env, downloads, profiles) = {
            let mut i = self.inner.borrow_mut();
            i.active = None;
            (
                std::mem::take(&mut i.tabs),
                i.env.take(),
                std::mem::take(&mut i.downloads),
                (i.std_profile.take(), i.temp_profile.take()),
            )
        };
        drop(profiles);
        for c in tabs.iter().filter_map(|t| t.controller.as_ref()) {
            // SAFETY: closing controllers we own.
            unsafe {
                let _ = c.Close();
            }
        }
        drop(tabs);
        drop(downloads);
        drop(env);
    }

    // ---------------------------------------------------------------- events

    fn update(&self, id: u32, f: impl FnOnce(&mut TabInfo)) {
        if self.with_tab(id, |t| f(&mut t.info)).is_some() {
            self.changed();
        }
    }

    fn with_tab<T>(&self, id: u32, f: impl FnOnce(&mut Tab) -> T) -> Option<T> {
        let mut i = self.inner.borrow_mut();
        i.tabs.iter_mut().find(|t| t.info.id == id).map(f)
    }

    fn tab_ref<T>(&self, id: u32, f: impl FnOnce(&Tab) -> T) -> Option<T> {
        let i = self.inner.borrow();
        i.tabs.iter().find(|t| t.info.id == id).map(f)
    }

    fn on_navigation_starting(&self, id: u32, a: &ICoreWebView2NavigationStartingEventArgs) {
        let mut nav_id = 0u64;
        // SAFETY: getters on live event args.
        let uri = unsafe {
            let _ = a.NavigationId(&mut nav_id);
            take_str(|p| a.Uri(p)).unwrap_or_default()
        };
        let decision = policy::navigation(&uri, &self.inner.borrow().https);
        match decision {
            // Links that hand off to another application (mailto:, zoommtg:, …) are not page
            // loads: the current page stays, and LaunchingExternalUriScheme decides.
            NavDecision::Allow if !is_web_scheme(&uri) => {}
            NavDecision::Allow => {
                // Questions from the page being left are answered "no".
                self.deny_pending(Some(id));
                // D-033: a listed site is never contacted; UNTRACE's warning replaces it.
                let threat = self.threat_for(&uri);
                if threat.is_some() {
                    // SAFETY: setter on live event args.
                    unsafe {
                        let _ = a.SetCancel(true);
                    }
                }
                self.with_tab(id, |t| {
                    if threat.is_some() {
                        t.note_cancelled(&uri);
                    }
                    if t.upgrade.as_ref().is_some_and(|u| u.https_url != uri) {
                        t.upgrade = None;
                    }
                    t.nav_id = nav_id;
                    t.nav_uri = uri.clone();
                    t.cert_error = None;
                    let cleaned = t.cleaned.take().filter(|(url, _)| *url == uri);
                    let i = &mut t.info;
                    i.loading = true;
                    i.crashed = false;
                    i.last_error = None;
                    i.http_status = None;
                    i.blocked = Blocked::default();
                    if let Some((_, names)) = cleaned {
                        i.blocked.add_params(&names); // removed on the way to this address
                    }
                    i.interstitial = None;
                    i.notice = None;
                    i.network = None;
                });
                // D-040: the user opened this name (or followed a link to it): it may point into
                // the local network, unless it pointed to the internet earlier this session.
                if threat.is_none()
                    && let Some(p) = self.proxy()
                {
                    p.announce_local(&host_of(&uri));
                }
                // M6: this site's own hiding rules.
                if threat.is_none() && (uri.starts_with("https://") || uri.starts_with("http://")) {
                    self.prepare_site_rules(id, &uri);
                }
                if let Some(list) = threat {
                    let l = untrace_filter::info(list);
                    self.set_interstitial(
                        id,
                        Interstitial::Threat {
                            url: uri.clone(),
                            host: host_of(&uri),
                            list,
                            list_title: l.title.into(),
                            list_homepage: l.homepage.into(),
                        },
                    );
                }
                self.layout();
                self.changed();
            }
            NavDecision::Upgrade(https) => {
                // SAFETY: setter on live event args.
                unsafe {
                    let _ = a.SetCancel(true);
                }
                let looped = self
                    .with_tab(id, |t| {
                        t.note_cancelled(&uri);
                        let hops = t
                            .upgrade
                            .as_ref()
                            .filter(|u| u.https_url == https)
                            .map(|u| u.hops)
                            .unwrap_or(0);
                        t.upgrade = Some(Upgrade {
                            https_url: https.clone(),
                            http_url: uri.clone(),
                            hops: hops + 1,
                        });
                        hops >= 2
                    })
                    .unwrap_or(false);
                if looped {
                    self.set_interstitial(
                        id,
                        Interstitial::HttpsUnavailable {
                            url: https.clone(),
                            http_url: uri.clone(),
                            host: host_of(&uri),
                            reason: "The site keeps sending UNTRACE back to an unencrypted address.".into(),
                        },
                    );
                } else {
                    let h = self.clone();
                    defer(move || h.navigate_tab(id, &https));
                }
            }
            NavDecision::Block(reason) => {
                // SAFETY: setter on live event args.
                unsafe {
                    let _ = a.SetCancel(true);
                }
                let text = match reason {
                    BlockReason::LocalFile => "UNTRACE blocked a link to a file on this computer.",
                    BlockReason::InternalPage => "UNTRACE blocked a link to an internal browser page.",
                };
                self.with_tab(id, |t| t.note_cancelled(&uri));
                self.update(id, |t| {
                    t.blocked.navigations += 1;
                    t.notice = Some(text.into());
                });
            }
        }
    }

    /// The malware/phishing list naming this page's host, unless the user continued to it.
    fn threat_for(&self, uri: &str) -> Option<ListId> {
        let i = self.inner.borrow();
        let list = i.filters.threat(uri)?;
        (!i.threat_exceptions.contains(&host_of(uri))).then_some(list)
    }

    /// Make sure exactly one live view also raises shared/service-worker requests. WebView2
    /// reports those to every view registered for them, so registering everywhere would
    /// check (and count) each one many times.
    fn claim_worker_requests(&self) {
        // Each profile has its own workers, so each has its own owner tab.
        self.claim_worker_requests_for(false);
        self.claim_worker_requests_for(true);
    }

    fn claim_worker_requests_for(&self, temporary: bool) {
        let candidate = {
            let i = self.inner.borrow();
            let owner = if temporary { i.temp_worker_owner } else { i.worker_owner };
            let owner_alive = owner.is_some_and(|o| i.tabs.iter().any(|t| t.info.id == o && t.webview.is_some()));
            if owner_alive {
                return;
            }
            i.tabs
                .iter()
                .filter(|t| t.info.temporary == temporary)
                .find_map(|t| t.webview.clone().map(|w| (t.info.id, w)))
        };
        let Some((id, wv)) = candidate else {
            let mut i = self.inner.borrow_mut();
            if temporary {
                i.temp_worker_owner = None;
            } else {
                i.worker_owner = None;
            }
            return;
        };
        // SAFETY: COM call on a live webview, outside any of its events.
        let ok = unsafe {
            wv.cast::<ICoreWebView2_22>().and_then(|wv22| {
                wv22.AddWebResourceRequestedFilterWithRequestSourceKinds(
                    w!("*"),
                    COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
                    COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_SHARED_WORKER
                        | COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_SERVICE_WORKER,
                )
            })
        }
        .is_ok();
        let mut i = self.inner.borrow_mut();
        match (ok, temporary) {
            (true, false) => i.worker_owner = Some(id),
            (true, true) => i.temp_worker_owner = Some(id),
            (false, _) => i.filter_registration_failed = true,
        }
    }

    fn on_resource_requested(&self, id: u32, a: &ICoreWebView2WebResourceRequestedEventArgs) {
        let mut ctx = COREWEBVIEW2_WEB_RESOURCE_CONTEXT(0);
        let mut kind = COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_DOCUMENT;
        // SAFETY: getters on live event args.
        let (uri, referer, method) = unsafe {
            let Ok(req) = a.Request() else { return };
            let _ = a.ResourceContext(&mut ctx);
            if let Ok(a2) = a.cast::<ICoreWebView2WebResourceRequestedEventArgs2>() {
                let _ = a2.RequestedSourceKind(&mut kind);
            }
            let uri = take_str(|p| req.Uri(p)).unwrap_or_default();
            let referer = req
                .Headers()
                .ok()
                .and_then(|h| take_str(|p| h.GetHeader(w!("Referer"), p)));
            let method = take_str(|p| req.Method(p)).unwrap_or_default();
            (uri, referer, method)
        };
        if !(uri.starts_with("https://") || uri.starts_with("http://")) {
            return;
        }
        // Self-check pages (map_folder): answered here, never sent anywhere.
        if self.serve_from_folder(&uri, a) {
            return;
        }
        let worker = kind != COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_DOCUMENT;
        // A navigation cancelled at NavigationStarting still sends its request (M5 probe: the
        // server received it, and over plain HTTP for HTTPS-only upgrades). Answer it here, so a
        // listed site is never contacted and no unencrypted request leaves.
        if !worker
            && ctx == COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT
            && self.with_tab(id, |t| t.take_cancelled(&uri)).unwrap_or(false)
        {
            let _ = self.respond_403(a);
            return;
        }
        // D-027: a page or frame address loses its tracking parameters before the request leaves:
        // the engine is told to load the cleaned address instead. Only GET requests (a form's
        // POST must keep its address and body).
        if !worker
            && ctx == COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT
            && method.eq_ignore_ascii_case("GET")
            && self.inner.borrow().strip_params
            && let Some(c) = untrace_filter::params::clean(&uri)
            && self.respond_redirect(a, &c.url)
        {
            self.with_tab(id, |t| {
                if t.nav_uri == uri {
                    // The redirect starts the navigation again, which resets the page's counts.
                    t.cleaned = Some((c.url.clone(), c.removed.clone()));
                }
                t.info.blocked.add_params(&c.removed);
            });
            self.changed();
            return;
        }
        // Requests belong to the tab's page; worker requests to whatever page the worker names
        // as referrer (or its own site): exceptions then follow that site. The tab also tells
        // which profile (and so which temporary exceptions) applies.
        let (page, temporary) = {
            let i = self.inner.borrow();
            let temporary = i.tabs.iter().any(|t| t.info.id == id && t.info.temporary);
            let page = if worker {
                referer.unwrap_or_else(|| uri.clone())
            } else {
                let Some(t) = i.tabs.iter().find(|t| t.info.id == id) else {
                    return;
                };
                if ctx == COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT && t.nav_uri == uri {
                    return; // the page itself: checked at NavigationStarting
                }
                if t.nav_uri.is_empty() {
                    t.info.url.clone()
                } else {
                    t.nav_uri.clone()
                }
            };
            (page, temporary)
        };
        if self.local_network_refused(&uri, &page, temporary) {
            if !self.respond_403(a) {
                return;
            }
            if worker {
                self.inner.borrow_mut().local_worker_blocked += 1;
                self.changed();
            } else {
                let host = host_of(&uri);
                self.update(id, |t| {
                    t.blocked.local_network += 1;
                    t.blocked.add_host(host, None, true);
                });
            }
            return;
        }
        let verdict = {
            let i = self.inner.borrow();
            let kind = resource_kind(ctx.0);
            match i.filters.threat(&uri) {
                Some(list) if !i.threat_exceptions.contains(&host_of(&uri)) => Some(Some(list)),
                _ => {
                    let excepted = registrable_domain(&page).is_some_and(|s| {
                        i.site_exceptions.contains(&s) || (temporary && i.temp_site_exceptions.contains(&s))
                    });
                    (!excepted && i.filters.content_blocks(&uri, &page, kind)).then_some(None)
                }
            }
        };
        let Some(threat) = verdict else { return };
        if !self.respond_403(a) {
            return;
        }
        if worker {
            self.inner.borrow_mut().worker_blocked += 1;
            self.changed();
        } else {
            let host = host_of(&uri);
            self.update(id, |t| {
                if threat.is_some() {
                    t.blocked.threats += 1;
                } else {
                    t.blocked.requests += 1;
                }
                t.blocked.add_host(host, threat, false);
            });
        }
    }

    /// Answer a request with an empty 403 (D-034). False if the engine refused.
    fn respond_403(&self, a: &ICoreWebView2WebResourceRequestedEventArgs) -> bool {
        let Some(env) = self.inner.borrow().env.clone() else {
            return false;
        };
        // SAFETY: creating a response object and handing it to live event args.
        unsafe {
            match env.CreateWebResourceResponse(None, 403, w!("Blocked by UNTRACE"), w!("Cache-Control: no-store")) {
                Ok(resp) => a.SetResponse(&resp).is_ok(),
                Err(_) => false,
            }
        }
    }

    /// D-040: a request from a public page to this computer or the local network is refused,
    /// unless the user allowed that site. Pages that are themselves local may reach the local
    /// network. When a page may, the public names it asks for are announced to the network
    /// layer, whose DNS-rebinding guard would otherwise refuse names that resolve locally.
    fn local_network_refused(&self, uri: &str, page: &str, temporary: bool) -> bool {
        let i = self.inner.borrow();
        let target = host_of(uri);
        let page_local = netaddr::page_space(&host_of(page)) != Space::Public;
        let allowed = || {
            registrable_domain(page)
                .is_some_and(|s| i.local_sites.contains(&s) || (temporary && i.temp_local_sites.contains(&s)))
        };
        match netaddr::host_space(&target) {
            Some(space) if space.is_local() => i.local_protect && !page_local && !allowed(),
            Some(_) => false,
            None => {
                if (page_local || allowed())
                    && let Some(p) = &i.cfg.network
                {
                    p.announce_local(&target);
                }
                false
            }
        }
    }

    /// Would a request from `page` to `target` be refused by D-040? (Self-check and UI.)
    pub fn local_network_blocks(&self, page: &str, target: &str, temporary: bool) -> bool {
        self.local_network_refused(target, page, temporary)
    }

    /// What the network layer knows about a page's host.
    fn page_network(&self, uri: &str) -> Option<PageNetwork> {
        let p = self.proxy()?;
        if !(uri.starts_with("https://") || uri.starts_with("http://")) {
            return None;
        }
        let host = host_of(uri);
        let rec = p.record(&host);
        Some(PageNetwork {
            through_network_layer: rec.as_ref().is_some_and(|r| r.connections > 0),
            dns: if netaddr::literal(&host).is_some() {
                Some(Via::Literal)
            } else {
                rec.as_ref().and_then(|r| r.via)
            },
            dns_server: rec.and_then(|r| r.dns_server),
        })
    }

    /// Why the network layer could not reach a page's host, if it recorded a reason.
    fn network_failure(&self, uri: &str) -> Option<String> {
        self.proxy()?.record(&host_of(uri))?.last_error
    }

    /// The proxy's challenge is answered with this launch's credentials; a site's own sign-in
    /// request is left to the engine. The proxy is recognised by its random realm, which no
    /// page can see.
    fn on_basic_auth(&self, a: &ICoreWebView2BasicAuthenticationRequestedEventArgs) {
        let Some(p) = self.proxy() else { return };
        // SAFETY: getters and setters on live event args.
        unsafe {
            let challenge = take_str(|x| a.Challenge(x)).unwrap_or_default();
            if !challenge.contains(p.realm()) {
                return;
            }
            let (user, pass) = p.credentials();
            if let Ok(r) = a.Response() {
                let _ = r.SetUserName(&HSTRING::from(user));
                let _ = r.SetPassword(&HSTRING::from(pass));
            }
        }
    }

    /// Answer a request with a redirect to `to` (same method and body: 307).
    fn respond_redirect(&self, a: &ICoreWebView2WebResourceRequestedEventArgs, to: &str) -> bool {
        if to.contains(['\r', '\n']) {
            return false;
        }
        let Some(env) = self.inner.borrow().env.clone() else {
            return false;
        };
        let headers = HSTRING::from(format!("Location: {to}\r\nCache-Control: no-store"));
        // SAFETY: creating a response object and handing it to live event args.
        unsafe {
            match env.CreateWebResourceResponse(None, 307, w!("Temporary Redirect"), &headers) {
                Ok(resp) => a.SetResponse(&resp).is_ok(),
                Err(_) => false,
            }
        }
    }

    fn on_navigation_completed(&self, id: u32, nav_id: u64, ok: bool, status: i32, http: i32) {
        // Only the page load this tab is tracking counts. Navigations UNTRACE cancelled (upgrades,
        // blocked schemes) and hand-offs to other applications complete under other ids.
        if self.tab_ref(id, |t| t.nav_id != nav_id).unwrap_or(true) {
            return;
        }
        let Some((nav_uri, up, cert)) =
            self.with_tab(id, |t| (t.nav_uri.clone(), t.upgrade.take(), t.cert_error.take()))
        else {
            return;
        };
        if !ok && status == 18 && self.proxy().is_some() {
            // D-026: the network layer's one-time challenge. UNTRACE answers it and the engine
            // retries by itself; this is not the page's error.
            self.with_tab(id, |t| t.upgrade = up);
            return;
        }
        if ok || status == 14 {
            // Success, or cancelled (usually replaced by a newer navigation).
            if status == 14 {
                self.with_tab(id, |t| t.upgrade = up);
            }
            let network = if ok { self.page_network(&nav_uri) } else { None };
            self.update(id, |t| {
                t.loading = false;
                t.network = network;
                if ok {
                    t.http_status = (http > 0).then_some(http);
                }
            });
            return;
        }
        // A refused certificate surfaces here as "aborted"; the certificate event carries the reason.
        let reason = match &cert {
            Some((r, _)) => r.clone(),
            None => self
                .network_failure(&nav_uri)
                .unwrap_or_else(|| web_error_name(status).to_string()),
        };
        self.update(id, |t| {
            t.last_error = Some(reason.clone());
            t.http_status = (http > 0).then_some(http);
        });
        let inter = match (up, cert) {
            (Some(u), _) if u.https_url == nav_uri || host_of(&u.https_url) == host_of(&nav_uri) => {
                Interstitial::HttpsUnavailable {
                    host: host_of(&u.http_url),
                    url: u.https_url,
                    http_url: u.http_url,
                    reason,
                }
            }
            (_, Some((_, certificate))) => Interstitial::Certificate {
                url: nav_uri.clone(),
                host: host_of(&nav_uri),
                reason,
                certificate,
            },
            _ if (1..=5).contains(&status) => Interstitial::Certificate {
                url: nav_uri.clone(),
                host: host_of(&nav_uri),
                reason,
                certificate: None,
            },
            _ => Interstitial::LoadError {
                url: nav_uri.clone(),
                host: host_of(&nav_uri),
                reason,
            },
        };
        self.set_interstitial(id, inter);
    }

    fn on_certificate_error(&self, id: u32, a: &ICoreWebView2ServerCertificateErrorDetectedEventArgs) {
        let mut status = COREWEBVIEW2_WEB_ERROR_STATUS(5);
        // SAFETY: setter/getters on live event args and the certificate they carry.
        let cert = unsafe {
            let _ = a.SetAction(COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_CANCEL); // D-008
            let _ = a.ErrorStatus(&mut status);
            a.ServerCertificate().ok().map(|c| {
                let (mut from, mut to) = (0f64, 0f64);
                let _ = c.ValidFrom(&mut from);
                let _ = c.ValidTo(&mut to);
                CertInfo {
                    subject: take_str(|p| c.Subject(p)).unwrap_or_default(),
                    issuer: take_str(|p| c.Issuer(p)).unwrap_or_default(),
                    valid_from: (from > 0.0).then_some(from),
                    valid_to: (to > 0.0).then_some(to),
                }
            })
        };
        let reason = web_error_name(status.0).to_string();
        self.with_tab(id, |t| t.cert_error = Some((reason, cert)));
        self.update(id, |t| t.blocked.certificate_errors += 1);
    }

    fn on_permission(&self, id: u32, a: &ICoreWebView2PermissionRequestedEventArgs) {
        let mut kind = COREWEBVIEW2_PERMISSION_KIND(0);
        // SAFETY: getters on live event args.
        let uri = unsafe {
            let _ = a.PermissionKind(&mut kind);
            take_str(|p| a.Uri(p)).unwrap_or_default()
        };
        let perm = permission_from(kind.0);
        let deny = |h: &ContentHost| {
            // SAFETY: setter on live event args.
            unsafe {
                let _ = a.SetState(COREWEBVIEW2_PERMISSION_STATE_DENY);
            }
            h.update(id, |t| t.blocked.permissions += 1);
        };
        if policy::permission(perm) == PermissionPolicy::Deny || self.prompts_open(id) >= MAX_PROMPTS_PER_TAB {
            deny(self);
            return;
        }
        // SAFETY: taking a deferral on live event args; completed in `respond`.
        let Ok(deferral) = (unsafe { a.GetDeferral() }) else {
            deny(self);
            return;
        };
        let detail = PromptDetail::Permission {
            permission: perm,
            label: perm.label().into(),
            phrase: perm.ask_phrase().into(),
        };
        self.add_prompt(
            id,
            origin_of(&uri),
            detail,
            deferral,
            PendingArgs::Permission(a.clone()),
        );
    }

    fn on_external_app(&self, id: u32, a: &ICoreWebView2LaunchingExternalUriSchemeEventArgs) {
        let mut user = BOOL(0);
        // SAFETY: getters on live event args.
        let (uri, origin) = unsafe {
            let _ = a.IsUserInitiated(&mut user);
            (
                take_str(|p| a.Uri(p)).unwrap_or_default(),
                take_str(|p| a.InitiatingOrigin(p)).unwrap_or_default(),
            )
        };
        let scheme = policy::scheme_of(&uri);
        let refuse = |h: &ContentHost, why: String| {
            // SAFETY: setter on live event args.
            unsafe {
                let _ = a.SetCancel(true);
            }
            h.update(id, |t| {
                t.blocked.external_apps += 1;
                t.notice = Some(why);
            });
        };
        match policy::external_scheme(&uri, user.as_bool()) {
            ExternalDecision::Deny(why) => refuse(
                self,
                format!("UNTRACE did not let this page open another application (\"{scheme}:\" {why})."),
            ),
            ExternalDecision::Prompt if self.prompts_open(id) >= MAX_PROMPTS_PER_TAB => refuse(
                self,
                "UNTRACE did not let this page open another application (too many requests).".into(),
            ),
            ExternalDecision::Prompt => {
                // SAFETY: taking a deferral on live event args; completed in `respond`.
                match unsafe { a.GetDeferral() } {
                    Ok(deferral) => {
                        let detail = PromptDetail::ExternalApp {
                            scheme,
                            target: shorten(&uri, 120),
                        };
                        // The engine reports "https://site/"; show the same form as other prompts.
                        let origin = if origin.is_empty() {
                            "This page".into()
                        } else {
                            origin_of(&origin)
                        };
                        self.add_prompt(id, origin, detail, deferral, PendingArgs::External(a.clone()));
                    }
                    Err(_) => refuse(self, "UNTRACE did not let this page open another application.".into()),
                }
            }
        }
    }

    fn on_download_starting(&self, id: u32, a: &ICoreWebView2DownloadStartingEventArgs) {
        let mut total = 0i64;
        // SAFETY: getters/setters on live event args.
        let (suggested, uri) = unsafe {
            let _ = a.SetHandled(true); // UNTRACE shows its own download UI
            let suggested = take_str(|p| a.ResultFilePath(p)).unwrap_or_default();
            let uri = a
                .DownloadOperation()
                .ok()
                .and_then(|op| {
                    let _ = op.TotalBytesToReceive(&mut total);
                    take_str(|p| op.Uri(p))
                })
                .unwrap_or_default();
            (PathBuf::from(suggested), uri)
        };
        let file_name = suggested
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "download".into());
        let risk = policy::download_risk(&file_name);
        if self.prompts_open(id) >= MAX_PROMPTS_PER_TAB {
            // SAFETY: setter on live event args.
            unsafe {
                let _ = a.SetCancel(true);
            }
            return;
        }
        // SAFETY: taking a deferral on live event args; completed in `respond`/`save_download`.
        let Ok(deferral) = (unsafe { a.GetDeferral() }) else {
            // SAFETY: setter on live event args.
            unsafe {
                let _ = a.SetCancel(true);
            }
            return;
        };
        let detail = PromptDetail::Download {
            file_name,
            size: (total > 0).then_some(total),
            risk,
        };
        // blob: URLs carry the creating page's origin; data: URLs have none.
        let origin = match uri.strip_prefix("blob:") {
            Some(inner) if inner.starts_with("https://") || inner.starts_with("http://") => origin_of(inner),
            _ if uri.starts_with("blob:") || uri.starts_with("data:") => "This page".into(),
            _ => origin_of(&uri),
        };
        self.add_prompt(
            id,
            origin,
            detail,
            deferral,
            PendingArgs::Download {
                args: a.clone(),
                suggested,
                risk,
            },
        );
    }

    fn on_security_state(&self, id: u32, json: &str) {
        let Some(origin) = self.tab_ref(id, |t| {
            let uri = if t.nav_uri.is_empty() { &t.info.url } else { &t.nav_uri };
            origin_of(uri)
        }) else {
            return;
        };
        if let Some(info) = ConnectionInfo::from_cdp(origin, json) {
            self.update(id, |t| t.connection = Some(info));
        }
    }

    fn wire(&self, id: u32, c: &ICoreWebView2Controller, wv: &ICoreWebView2) {
        let mut tok = 0i64;
        macro_rules! weak {
            () => {
                self.weak()
            };
        }
        // SAFETY (whole block): registering event handlers on a live controller/webview. Each
        // handler holds only a Weak reference and the tab id.
        unsafe {
            // M3: every request this view's documents make (frames included) is checked.
            let registered = wv.cast::<ICoreWebView2_22>().and_then(|wv22| {
                wv22.AddWebResourceRequestedFilterWithRequestSourceKinds(
                    w!("*"),
                    COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
                    COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_DOCUMENT,
                )
            });
            let w = weak!();
            let handler = wv.add_WebResourceRequested(
                &WebResourceRequestedEventHandler::create(Box::new(move |_, args| {
                    if let (Some(h), Some(a)) = (upgrade(&w), args) {
                        h.on_resource_requested(id, &a);
                    }
                    Ok(())
                })),
                &mut tok,
            );
            if registered.is_err() || handler.is_err() {
                self.inner.borrow_mut().filter_registration_failed = true;
            }
            // Connection security, read back from the engine through the DevTools protocol.
            // This channel is host-side only; pages cannot observe or use it.
            if let Ok(rx) = wv.GetDevToolsProtocolEventReceiver(w!("Security.visibleSecurityStateChanged")) {
                let w = weak!();
                let _ = rx.add_DevToolsProtocolEventReceived(
                    &DevToolsProtocolEventReceivedEventHandler::create(Box::new(move |_, args| {
                        if let (Some(h), Some(a)) = (upgrade(&w), args)
                            && let Some(json) = take_str(|p| a.ParameterObjectAsJson(p))
                        {
                            h.on_security_state(id, &json);
                        }
                        Ok(())
                    })),
                    &mut tok,
                );
                let _ = wv.CallDevToolsProtocolMethod(
                    w!("Security.enable"),
                    w!("{}"),
                    &CallDevToolsProtocolMethodCompletedHandler::create(Box::new(|_, _| Ok(()))),
                );
            }
            let w = weak!();
            let _ = wv.add_SourceChanged(
                &SourceChangedEventHandler::create(Box::new(move |s, _| {
                    if let (Some(h), Some(s)) = (upgrade(&w), s)
                        && let Some(url) = take_str(|p| s.Source(p))
                    {
                        h.update(id, |t| t.url = url);
                    }
                    Ok(())
                })),
                &mut tok,
            );
            let w = weak!();
            let _ = wv.add_DocumentTitleChanged(
                &DocumentTitleChangedEventHandler::create(Box::new(move |s, _| {
                    if let (Some(h), Some(s)) = (upgrade(&w), s)
                        && let Some(title) = take_str(|p| s.DocumentTitle(p))
                    {
                        let title: String = title.chars().take(300).collect();
                        h.update(id, |t| t.title = title);
                    }
                    Ok(())
                })),
                &mut tok,
            );
            let w = weak!();
            let _ = wv.add_NavigationStarting(
                &NavigationStartingEventHandler::create(Box::new(move |_, args| {
                    if let (Some(h), Some(a)) = (upgrade(&w), args) {
                        h.on_navigation_starting(id, &a);
                    }
                    Ok(())
                })),
                &mut tok,
            );
            let w = weak!();
            let _ = wv.add_NavigationCompleted(
                &NavigationCompletedEventHandler::create(Box::new(move |_, args| {
                    if let Some(h) = upgrade(&w) {
                        let (mut ok, mut status, mut http) = (BOOL(1), COREWEBVIEW2_WEB_ERROR_STATUS(0), 0i32);
                        let mut nav_id = 0u64;
                        if let Some(a) = &args {
                            let _ = a.IsSuccess(&mut ok);
                            let _ = a.WebErrorStatus(&mut status);
                            let _ = a.NavigationId(&mut nav_id);
                            if let Ok(a2) = a.cast::<ICoreWebView2NavigationCompletedEventArgs2>() {
                                let _ = a2.HttpStatusCode(&mut http);
                            }
                        }
                        h.on_navigation_completed(id, nav_id, ok.as_bool(), status.0, http);
                    }
                    Ok(())
                })),
                &mut tok,
            );
            let w = weak!();
            let _ = wv.add_HistoryChanged(
                &HistoryChangedEventHandler::create(Box::new(move |s, _| {
                    if let (Some(h), Some(s)) = (upgrade(&w), s) {
                        let (mut b, mut f) = (BOOL(0), BOOL(0));
                        let _ = s.CanGoBack(&mut b);
                        let _ = s.CanGoForward(&mut f);
                        h.update(id, |t| {
                            t.can_go_back = b.as_bool();
                            t.can_go_forward = f.as_bool();
                        });
                    }
                    Ok(())
                })),
                &mut tok,
            );
            if let Ok(w15) = wv.cast::<ICoreWebView2_15>() {
                let w = weak!();
                let w15b = w15.clone();
                let _ = w15.add_FaviconChanged(
                    &FaviconChangedEventHandler::create(Box::new(move |_, _| {
                        let w2 = w.clone();
                        let h = GetFaviconCompletedHandler::create(Box::new(move |hr, stream| {
                            let icon = match (hr, stream) {
                                (Ok(()), Some(s)) => {
                                    com::read_stream(&s, FAVICON_LIMIT).and_then(|b| com::favicon_data_url(&b))
                                }
                                _ => None,
                            };
                            if let Some(host) = upgrade(&w2) {
                                host.update(id, |t| t.favicon = icon);
                            }
                            Ok(())
                        }));
                        let _ = w15b.GetFavicon(COREWEBVIEW2_FAVICON_IMAGE_FORMAT_PNG, &h);
                        Ok(())
                    })),
                    &mut tok,
                );
            }
            let w = weak!();
            let _ = wv.add_NewWindowRequested(
                &NewWindowRequestedEventHandler::create(Box::new(move |_, args| {
                    let (Some(h), Some(a)) = (upgrade(&w), args) else {
                        return Ok(());
                    };
                    let mut user = BOOL(0);
                    let _ = a.IsUserInitiated(&mut user);
                    a.SetHandled(true)?;
                    if !user.as_bool() {
                        h.update(id, |t| t.blocked.popups += 1);
                        return Ok(()); // pop-ups without a user gesture are not opened
                    }
                    let deferral = a.GetDeferral()?;
                    let args = a.clone();
                    // A pop-up shares its opener's profile (the engine requires it, and a
                    // temporary tab's pop-up must stay temporary).
                    let temporary = h.tab_ref(id, |t| t.info.temporary).unwrap_or(false);
                    defer(move || {
                        h.new_tab_inner(
                            None,
                            Some(Box::new(move |nwv: &ICoreWebView2| {
                                let _ = args.SetNewWindow(nwv);
                                let _ = deferral.Complete();
                            })),
                            temporary,
                        );
                    });
                    Ok(())
                })),
                &mut tok,
            );
            let w = weak!();
            let _ = wv.add_WindowCloseRequested(
                &WindowCloseRequestedEventHandler::create(Box::new(move |_, _| {
                    if let Some(h) = upgrade(&w) {
                        defer(move || h.close_tab(id));
                    }
                    Ok(())
                })),
                &mut tok,
            );
            let w = weak!();
            let _ = wv.add_ProcessFailed(
                &ProcessFailedEventHandler::create(Box::new(move |_, args| {
                    let (Some(h), Some(a)) = (upgrade(&w), args) else {
                        return Ok(());
                    };
                    let mut kind = COREWEBVIEW2_PROCESS_FAILED_KIND(0);
                    let _ = a.ProcessFailedKind(&mut kind);
                    if kind == COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED {
                        h.fail("The browser engine stopped. Restart UNTRACE.".into());
                    } else if kind == COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_EXITED
                        || kind == COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_UNRESPONSIVE
                    {
                        h.update(id, |t| {
                            t.crashed = true;
                            t.loading = false;
                        });
                    }
                    Ok(())
                })),
                &mut tok,
            );
            let w = weak!();
            let _ = wv.add_PermissionRequested(
                &PermissionRequestedEventHandler::create(Box::new(move |_, args| {
                    if let (Some(h), Some(a)) = (upgrade(&w), args) {
                        h.on_permission(id, &a);
                    }
                    Ok(())
                })),
                &mut tok,
            );
            if let Ok(w18) = wv.cast::<ICoreWebView2_18>() {
                let w = weak!();
                let _ = w18.add_LaunchingExternalUriScheme(
                    &LaunchingExternalUriSchemeEventHandler::create(Box::new(move |_, args| {
                        if let (Some(h), Some(a)) = (upgrade(&w), args) {
                            h.on_external_app(id, &a);
                        }
                        Ok(())
                    })),
                    &mut tok,
                );
            }
            {
                let w = weak!();
                let _ = wv.add_ContentLoading(
                    &ContentLoadingEventHandler::create(Box::new(move |_, _| {
                        if let Some(h) = upgrade(&w) {
                            h.on_content_loading(id);
                        }
                        Ok(())
                    })),
                    &mut tok,
                );
            }
            if let Ok(w10) = wv.cast::<ICoreWebView2_10>() {
                let w = weak!();
                let _ = w10.add_BasicAuthenticationRequested(
                    &BasicAuthenticationRequestedEventHandler::create(Box::new(move |_, args| {
                        if let (Some(h), Some(a)) = (upgrade(&w), args) {
                            h.on_basic_auth(&a);
                        }
                        Ok(())
                    })),
                    &mut tok,
                );
            }
            if let Ok(w14) = wv.cast::<ICoreWebView2_14>() {
                let w = weak!();
                let _ = w14.add_ServerCertificateErrorDetected(
                    &ServerCertificateErrorDetectedEventHandler::create(Box::new(move |_, args| {
                        if let Some(a) = args {
                            match upgrade(&w) {
                                Some(h) => h.on_certificate_error(id, &a),
                                None => a.SetAction(COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_CANCEL)?,
                            }
                        }
                        Ok(())
                    })),
                    &mut tok,
                );
            }
            if let Ok(w4) = wv.cast::<ICoreWebView2_4>() {
                let w = weak!();
                let _ = w4.add_DownloadStarting(
                    &DownloadStartingEventHandler::create(Box::new(move |_, args| {
                        if let Some(a) = args {
                            match upgrade(&w) {
                                Some(h) => h.on_download_starting(id, &a),
                                None => a.SetCancel(true)?,
                            }
                        }
                        Ok(())
                    })),
                    &mut tok,
                );
            }
            let w = weak!();
            let _ = c.add_AcceleratorKeyPressed(
                &AcceleratorKeyPressedEventHandler::create(Box::new(move |_, args| {
                    if let (Some(h), Some(a)) = (upgrade(&w), args) {
                        h.on_accelerator(&a);
                    }
                    Ok(())
                })),
                &mut tok,
            );
        }
    }

    fn on_accelerator(&self, a: &ICoreWebView2AcceleratorKeyPressedEventArgs) {
        let mut kind = COREWEBVIEW2_KEY_EVENT_KIND(0);
        let mut vk = 0u32;
        let mut status = COREWEBVIEW2_PHYSICAL_KEY_STATUS::default();
        // SAFETY: getters on live event args; GetKeyState reads this thread's key state.
        let (ctrl, shift, alt) = unsafe {
            let _ = a.KeyEventKind(&mut kind);
            let _ = a.VirtualKey(&mut vk);
            let _ = a.PhysicalKeyStatus(&mut status);
            (
                GetKeyState(VK_CONTROL.0 as i32) < 0,
                GetKeyState(VK_SHIFT.0 as i32) < 0,
                GetKeyState(VK_MENU.0 as i32) < 0,
            )
        };
        if kind != COREWEBVIEW2_KEY_EVENT_KIND_KEY_DOWN && kind != COREWEBVIEW2_KEY_EVENT_KIND_SYSTEM_KEY_DOWN {
            return;
        }
        let key = |c: u8| vk == c as u32;
        enum Act {
            Focus,
            NewTab,
            NewTemporary,
            Close,
            Next,
            Prev,
            Bookmark,
        }
        let act = if (ctrl && !shift && !alt && key(b'L'))
            || (alt && !ctrl && key(b'D'))
            || (!ctrl && !alt && vk == VK_F6.0 as u32)
        {
            Some(Act::Focus)
        } else if ctrl && !alt && (key(b'T') || key(b'N')) && !shift {
            Some(Act::NewTab)
        } else if ctrl && !alt && (key(b'W') || vk == VK_F4.0 as u32) {
            Some(Act::Close)
        } else if ctrl && vk == VK_TAB.0 as u32 {
            Some(if shift { Act::Prev } else { Act::Next })
        } else if ctrl && shift && !alt && key(b'N') {
            Some(Act::NewTemporary) // never the engine's own InPrivate window
        } else if ctrl && !shift && !alt && key(b'D') {
            Some(Act::Bookmark)
        } else {
            None
        };
        let Some(act) = act else { return };
        // SAFETY: setter on live event args.
        unsafe {
            let _ = a.SetHandled(true);
        }
        if status.WasKeyDown.as_bool() && !matches!(act, Act::Next | Act::Prev) {
            return; // auto-repeat
        }
        let h = self.clone();
        defer(move || match act {
            Act::Focus => {
                let notify = h.inner.borrow().notify.clone();
                notify(HostEvent::FocusAddress);
            }
            Act::NewTab => {
                h.new_tab(None);
                let notify = h.inner.borrow().notify.clone();
                notify(HostEvent::FocusAddress);
            }
            Act::NewTemporary => {
                h.new_temporary_tab(None);
                let notify = h.inner.borrow().notify.clone();
                notify(HostEvent::FocusAddress);
            }
            Act::Close => {
                if let Some(id) = h.active_id() {
                    h.close_tab(id);
                }
            }
            Act::Next => h.cycle(true),
            Act::Prev => h.cycle(false),
            Act::Bookmark => {
                let notify = h.inner.borrow().notify.clone();
                notify(HostEvent::Bookmark);
            }
        });
    }
}

fn interstitial_url(i: &Interstitial) -> String {
    match i {
        Interstitial::HttpsUnavailable { url, .. }
        | Interstitial::Certificate { url, .. }
        | Interstitial::LoadError { url, .. }
        | Interstitial::Threat { url, .. } => url.clone(),
    }
}

fn set_tracking_level(p: &ICoreWebView2Profile, level: i32) -> windows::core::Result<()> {
    let p3: ICoreWebView2Profile3 = p.cast()?;
    // SAFETY: COM setter on a live profile.
    unsafe { p3.SetPreferredTrackingPreventionLevel(COREWEBVIEW2_TRACKING_PREVENTION_LEVEL(level)) }
}

fn set_color_scheme(p: &ICoreWebView2Profile, s: PageColorScheme) -> windows::core::Result<()> {
    let v = match s {
        PageColorScheme::Auto => COREWEBVIEW2_PREFERRED_COLOR_SCHEME_AUTO,
        PageColorScheme::Light => COREWEBVIEW2_PREFERRED_COLOR_SCHEME_LIGHT,
        PageColorScheme::Dark => COREWEBVIEW2_PREFERRED_COLOR_SCHEME_DARK,
    };
    // SAFETY: COM setter on a live profile.
    unsafe { p.SetPreferredColorScheme(v) }
}

fn read_color_scheme(p: &ICoreWebView2Profile) -> Option<PageColorScheme> {
    let mut v = COREWEBVIEW2_PREFERRED_COLOR_SCHEME_AUTO;
    // SAFETY: COM getter on a live profile.
    unsafe { p.PreferredColorScheme(&mut v) }.ok()?;
    match v {
        COREWEBVIEW2_PREFERRED_COLOR_SCHEME_AUTO => Some(PageColorScheme::Auto),
        COREWEBVIEW2_PREFERRED_COLOR_SCHEME_LIGHT => Some(PageColorScheme::Light),
        COREWEBVIEW2_PREFERRED_COLOR_SCHEME_DARK => Some(PageColorScheme::Dark),
        _ => None,
    }
}

fn read_tracking_level(p: &ICoreWebView2Profile) -> Option<i32> {
    let p3: ICoreWebView2Profile3 = p.cast().ok()?;
    let mut lvl = COREWEBVIEW2_TRACKING_PREVENTION_LEVEL(-1);
    // SAFETY: COM getter on a live profile.
    unsafe { p3.PreferredTrackingPreventionLevel(&mut lvl) }.ok()?;
    Some(lvl.0)
}

/// D-028: remove what closed temporary sessions left in the content data folder (the engine
/// leaves an almost empty folder per InPrivate profile). Call before the engine starts.
/// Returns how many folders were removed.
pub fn remove_leftover_temp_profiles(data_dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(data_dir.join("EBWebView")) else {
        return 0;
    };
    let mut removed = 0;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_ascii_lowercase();
        let temp = name
            .strip_prefix("wv2profile_")
            .unwrap_or(&name)
            .starts_with(TEMP_PROFILE_PREFIX);
        if temp && e.file_type().is_ok_and(|t| t.is_dir()) && std::fs::remove_dir_all(e.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

fn set_background(c: &ICoreWebView2Controller, rgb: [u8; 3]) -> windows::core::Result<()> {
    let c2: ICoreWebView2Controller2 = c.cast()?;
    // SAFETY: COM setter on a live controller.
    unsafe {
        c2.SetDefaultBackgroundColor(COREWEBVIEW2_COLOR {
            A: 255,
            R: rgb[0],
            G: rgb[1],
            B: rgb[2],
        })
    }
}

/// Content-view hardening. Failure to apply any of it closes the tab rather than running unprotected.
fn configure(
    c: &ICoreWebView2Controller,
    wv: &ICoreWebView2,
    devtools: bool,
    bg: [u8; 3],
) -> windows::core::Result<()> {
    // SAFETY: COM setters on a freshly created controller/webview.
    unsafe {
        let s = wv.Settings()?;
        s.SetIsWebMessageEnabled(false)?; // no host bridge
        s.SetAreHostObjectsAllowed(false)?; // no host bridge
        s.SetAreDevToolsEnabled(devtools)?;
        s.SetIsStatusBarEnabled(true)?; // link targets (engine status bar)
        s.SetIsBuiltInErrorPageEnabled(false)?; // UNTRACE shows its own error panels (M2)
        let s4: ICoreWebView2Settings4 = s.cast()?;
        s4.SetIsPasswordAutosaveEnabled(false)?;
        s4.SetIsGeneralAutofillEnabled(false)?;
        let s8: ICoreWebView2Settings8 = s.cast()?;
        s8.SetIsReputationCheckingRequired(false)?; // D-012: SmartScreen off by default
    }
    set_background(c, bg)
}

impl Applier for ContentHost {
    fn apply(&mut self, id: &str, value: &Value) -> std::result::Result<(), String> {
        match (id, value) {
            (DEVTOOLS_ID, Value::Bool(on)) => self.set_devtools(*on),
            (HTTPS_ONLY_ID, Value::Bool(on)) => {
                let mut i = self.inner.borrow_mut();
                i.https.enabled = *on;
                i.cfg.https_only = *on;
                Ok(())
            }
            (TRACKING_PREVENTION_ID, Value::Choice(level)) => self.set_tracking_prevention(level),
            (STRIP_PARAMS_ID, Value::Bool(on)) => {
                self.inner.borrow_mut().strip_params = *on;
                Ok(())
            }
            (HIDE_ELEMENTS_ID, Value::Bool(on)) => {
                self.inner.borrow_mut().cosmetic_on = *on;
                self.refresh_cosmetic();
                Ok(())
            }
            // Written into the engine's profiles when it starts (Scope::Environment).
            (WEBRTC_ID, Value::Bool(_)) => Ok(()),
            (LOCAL_NETWORK_ID, Value::Bool(on)) => {
                self.inner.borrow_mut().local_protect = *on;
                if let Some(p) = self.proxy() {
                    p.set_local_guard(*on);
                }
                Ok(())
            }
            _ => Err(format!("no applier for \"{id}\"")),
        }
    }

    fn observe(&self, id: &str) -> Observed {
        match id {
            DEVTOOLS_ID => self.observe_devtools(),
            // Enforced by UNTRACE's own navigation policy, which reports its state here; the
            // behaviour itself is exercised end to end by the self-check.
            HTTPS_ONLY_ID => Observed::Verified(Value::Bool(self.inner.borrow().https.enabled)),
            TRACKING_PREVENTION_ID => self.observe_tracking_prevention(),
            // UNTRACE's own request policy; exercised end to end by the self-check.
            STRIP_PARAMS_ID => Observed::Verified(Value::Bool(self.inner.borrow().strip_params)),
            // The script each tab carries; hiding itself is exercised by the self-check.
            HIDE_ELEMENTS_ID => self.observe_cosmetic(),
            // UNTRACE's request policy (and the network layer's guard); exercised end to end by
            // the self-check.
            LOCAL_NETWORK_ID => {
                let i = self.inner.borrow();
                let guard = i
                    .cfg
                    .network
                    .as_ref()
                    .is_none_or(|p| p.local_guard() == i.local_protect);
                if i.filter_registration_failed {
                    Observed::Unverifiable("the browser engine refused to let UNTRACE check requests".into())
                } else if !guard {
                    Observed::Unverifiable("the network layer reports a different state".into())
                } else {
                    Observed::Verified(Value::Bool(i.local_protect))
                }
            }
            // Read back from the engine's profile files UNTRACE wrote before the engine loaded
            // them; the behaviour itself is exercised end to end by the self-check.
            WEBRTC_ID => self.observe_webrtc(),
            _ => Observed::Unverifiable("not implemented".into()),
        }
    }
}
