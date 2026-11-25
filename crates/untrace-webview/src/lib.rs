//! UNTRACE content views.
//!
//! Web content runs in WebView2 controllers created here — never in Tauri webviews — inside an
//! UNTRACE-owned child window that sits above the UI view (M0/S1). Content views get no host
//! bridge: no host objects, no web messages, no injected application code.
//!
//! Everything in this crate runs on the UI thread (WebView2 is single-threaded apartment).
//! `unsafe` is confined to WebView2/Win32 FFI calls on COM pointers obtained from the runtime.

mod com;
mod container;
mod dialog;
mod engine_files;
mod host;

pub use container::defer;
pub use dialog::{open_file, save_as};
pub use engine_files::{ScrubReport, WEBRTC_PROXY_ONLY, scrub_engine_files};
pub use host::{
    Blocked, BlockedHost, CertInfo, ClearKinds, ConnectionInfo, ContentHost, CookieSite, DEVTOOLS_ID, DownloadInfo,
    EngineInfo, HIDE_ELEMENTS_ID, HTTPS_ONLY_ID, HostConfig, HostEvent, Interstitial, LOCAL_NETWORK_ID,
    MIN_RUNTIME_MAJOR, NetworkCheck, Notify, PageColorScheme, PageNetwork, PromptDetail, PromptInfo, STRIP_PARAMS_ID,
    Snapshot, StoredPermission, TEMP_PROFILE_PREFIX, TRACKING_LEVELS, TRACKING_PREVENTION_ID, TabInfo, WEBRTC_ID,
    remove_leftover_temp_profiles,
};
