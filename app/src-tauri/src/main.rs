//! UNTRACE desktop shell (Tauri 2).
//!
//! The Tauri window hosts only UNTRACE's own interface. Web content lives in raw WebView2
//! controllers owned by `untrace-webview`, inside a container window above the UI view.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod appearance;
mod appupdate;
mod commands;
mod fetch;
mod filters;
mod network;
mod platform;
mod privacy;
mod protections;
mod report;
mod selfcheck;
mod selftest;

use std::{
    cell::{Cell, RefCell},
    path::PathBuf,
    rc::Rc,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::ThreadId,
};

use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent};
use untrace_core::{
    audit::{AuditEvent, AuditLog},
    paths::{self, Layout},
    registry::{Registry, Value},
    settings::Theme,
    store::{LoadOutcome, SettingsStore},
};
use untrace_webview::{ContentHost, DEVTOOLS_ID, HTTPS_ONLY_ID, HostConfig, HostEvent, NetworkCheck, Notify};
use webview2_com::Microsoft::Web::WebView2::Win32::{
    COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC, ICoreWebView2Settings3,
};
use windows::{Win32::Foundation::RECT, core::Interface};

/// Content area as reported by the UI, in device-independent pixels.
#[derive(Clone, Copy, Debug)]
pub struct ContentRect {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
    pub visible: bool,
}

pub struct AppState {
    pub store: Mutex<SettingsStore>,
    pub audit: AuditLog,
    pub registry: Registry,
    pub layout: Layout,
    pub config_status: LoadOutcome,
    pub content_dip: Mutex<Option<ContentRect>>,
    pub host_error: Mutex<Option<String>>,
    pub main_thread: ThreadId,
    pub filters: filters::FilterService,
    pub exit_clear: privacy::ExitClear,
    /// What the start-up clean-up of the engine's own files did (D-039).
    pub engine_scrub: Mutex<Option<untrace_webview::ScrubReport>>,
    /// The M5 network layer, started in `setup` before the engine.
    pub network: std::sync::OnceLock<network::NetworkService>,
    /// M7: the self-check run from Diagnostics, and its last report.
    pub selftest: selftest::SelfTest,
    /// This instance is the self-check (`--self-check`): no welcome screen.
    pub self_check: bool,
    /// M9: UNTRACE's own updates (D-016).
    pub app_updates: appupdate::AppUpdates,
}

impl AppState {
    pub fn network(&self) -> &network::NetworkService {
        self.network
            .get_or_init(|| network::NetworkService::start("off", "quad9", None))
    }
}

thread_local! {
    static HOST: RefCell<Option<ContentHost>> = const { RefCell::new(None) };
    static EMIT_PENDING: Cell<bool> = const { Cell::new(false) };
}

/// Navigations of the UI view away from the app origin that were refused.
pub static UI_NAV_BLOCKED: AtomicUsize = AtomicUsize::new(0);
static ENGINE_LOGGED: AtomicBool = AtomicBool::new(false);
static NETWORK_CHECK_LOGGED: AtomicBool = AtomicBool::new(false);

/// The content host (UI thread only). Cloning is cheap (reference-counted).
pub fn host() -> Option<ContentHost> {
    HOST.with(|h| h.borrow().clone())
}

fn is_app_url(u: &tauri::Url) -> bool {
    matches!(
        (u.scheme(), u.host_str()),
        ("http" | "https", Some("tauri.localhost")) | ("tauri", Some("localhost"))
    )
}

pub fn content_background(app: &AppHandle, theme: Theme) -> [u8; 3] {
    if theme == Theme::Black {
        return [0, 0, 0];
    }
    let dark = match theme {
        Theme::Dark | Theme::Black => true,
        Theme::Light => false,
        Theme::System => app
            .get_webview_window("main")
            .and_then(|w| w.theme().ok())
            .map(|t| t == tauri::Theme::Dark)
            .unwrap_or(true),
    };
    if dark { [14, 14, 15] } else { [255, 255, 255] }
}

/// Map the UI's content rectangle (DIP) to physical pixels and place the content container.
pub fn apply_bounds(app: &AppHandle) {
    let state = app.state::<AppState>();
    let Some(r) = *state.content_dip.lock().unwrap() else {
        return;
    };
    let Some(w) = app.get_webview_window("main") else {
        return;
    };
    let s = w.scale_factor().unwrap_or(1.0);
    let rect = RECT {
        left: (r.x * s).round() as i32,
        top: (r.y * s).round() as i32,
        right: ((r.x + r.w) * s).round() as i32,
        bottom: ((r.y + r.h) * s).round() as i32,
    };
    if let Some(h) = host() {
        h.set_bounds(rect, r.visible);
    }
}

/// Move keyboard focus to the UI view and tell it which element to focus.
fn focus_ui(app: &AppHandle, event: &'static str) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.set_focus();
        let _ = w.with_webview(|pw| {
            // SAFETY: COM call on the UI view's live controller, on the UI thread.
            unsafe {
                let _ = pw.controller().MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
            }
        });
        let _ = w.emit_to("main", event, ());
    }
}

/// Coalesce bursts of tab changes into one event per message-loop turn.
fn schedule_emit(app: &AppHandle) {
    if EMIT_PENDING.with(|p| p.replace(true)) {
        return;
    }
    let app = app.clone();
    untrace_webview::defer(move || {
        EMIT_PENDING.with(|p| p.set(false));
        let Some(h) = host() else { return };
        let snap = h.snapshot();
        if let Some(v) = &snap.runtime_version
            && !ENGINE_LOGGED.swap(true, Ordering::SeqCst)
        {
            let _ = app.state::<AppState>().audit.record(AuditEvent::EngineReady {
                runtime_version: v.clone(),
            });
        }
        let state = match h.network_check() {
            NetworkCheck::Passed { ms } => Some(format!("start-up check passed in {ms} ms")),
            NetworkCheck::Failed { reason } => Some(format!("start-up check failed: {reason}")),
            _ => None,
        };
        if let Some(state) = state
            && !NETWORK_CHECK_LOGGED.swap(true, Ordering::SeqCst)
        {
            let _ = app.state::<AppState>().audit.record(AuditEvent::NetworkLayer { state });
        }
        let _ = app.emit_to("main", "tabs", &snap);
    });
}

fn on_host_event(app: &AppHandle, ev: HostEvent) {
    match ev {
        HostEvent::Changed => schedule_emit(app),
        HostEvent::FocusAddress => focus_ui(app, "focus-address"),
        HostEvent::FocusPanel => focus_ui(app, "focus-panel"),
    }
}

/// The UI view only ever shows UNTRACE's bundled interface: no context menu, no browser
/// shortcuts (F5, Ctrl+P …), no zoom, no status bar.
fn harden_ui_view(w: &WebviewWindow) {
    let _ = w.with_webview(|pw| {
        // SAFETY: COM setters on the UI view's live webview, on the UI thread.
        unsafe {
            if let Ok(core) = pw.controller().CoreWebView2()
                && let Ok(s) = core.Settings()
            {
                let _ = s.SetAreDefaultContextMenusEnabled(cfg!(debug_assertions));
                let _ = s.SetIsStatusBarEnabled(false);
                let _ = s.SetIsZoomControlEnabled(false);
                if let Ok(s3) = s.cast::<ICoreWebView2Settings3>() {
                    let _ = s3.SetAreBrowserAcceleratorKeysEnabled(false);
                }
            }
        }
    });
}

fn setup(app: &mut tauri::App, self_check: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let handle = app.handle().clone();
    appupdate::init(&handle);
    let state = app.state::<AppState>();
    // M5: the network layer starts before anything can use it (D-006, D-023).
    {
        let store = state.store.lock().unwrap();
        let choice = |id: &str| {
            let def = state.registry.get(id).expect("protection def");
            state.registry.configured(&store, def).to_string()
        };
        let (mode, provider) = (choice(network::DNS_MODE_ID), choice(network::DOH_PROVIDER_ID));
        let custom = store.settings().custom_doh.clone();
        drop(store);
        let net = network::NetworkService::start(&mode, &provider, custom.as_ref());
        let audit = match (net.proxy(), net.start_error()) {
            (Some(p), _) => Some(format!("started ({mode}) on 127.0.0.1:{}", p.port())),
            (None, Some(e)) => Some(e.to_string()),
            _ => None,
        };
        if let Some(state_text) = audit {
            let _ = state.audit.record(AuditEvent::NetworkLayer { state: state_text });
        }
        let _ = state.network.set(net);
    }
    state.selftest.load();
    let win = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        // A self-check run from Diagnostics opens a second window; its title says what it is.
        .title(if self_check.is_some() {
            "UNTRACE self-check"
        } else {
            "UNTRACE"
        })
        .inner_size(1280.0, 840.0)
        .min_inner_size(720.0, 480.0)
        .visible(false) // shown once the UI has rendered (ui_ready)
        .data_directory(state.layout.ui_webview.clone())
        .on_navigation(|url| {
            let ok = is_app_url(url);
            if !ok {
                UI_NAV_BLOCKED.fetch_add(1, Ordering::SeqCst);
            }
            ok
        })
        .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
        .build()?;
    harden_ui_view(&win);

    let (devtools, https_only, theme) = {
        let store = state.store.lock().unwrap();
        let on = |id: &str| {
            let def = state.registry.get(id).expect("protection def");
            state.registry.configured(&store, def) == Value::Bool(true)
        };
        (on(DEVTOOLS_ID), on(HTTPS_ONLY_ID), store.settings().theme)
    };
    // Housekeeping before the engine starts (here, not in main(): only the first instance gets
    // this far, so a second launch never touches a running session's folders).
    let pruned = privacy::prune_crash_reports(
        &privacy::crash_report_dirs(&state.layout),
        std::time::Duration::from_secs(privacy::CRASH_REPORT_DAYS * 24 * 3600),
    );
    // D-039/D-028: the engine's own records of visited sites and of temporary profiles.
    let scrub = untrace_webview::scrub_engine_files(&state.layout.content_webview);
    if pruned > 0 {
        let _ = state.audit.record(AuditEvent::DataCleared {
            what: format!(
                "{pruned} crash report(s) older than {} days",
                privacy::CRASH_REPORT_DAYS
            ),
            ok: true,
        });
    }
    if scrub.engagement_removed + scrub.temp_profile_entries_removed + scrub.temp_folders_removed > 0
        || !scrub.problems.is_empty()
    {
        let _ = state.audit.record(AuditEvent::DataCleared {
            what: format!(
                "engine records at start: {} site-engagement record(s), {} temporary-profile entries, {} temporary folder(s)",
                scrub.engagement_removed, scrub.temp_profile_entries_removed, scrub.temp_folders_removed
            ),
            ok: scrub.verified,
        });
    }
    *state.engine_scrub.lock().unwrap() = Some(scrub);
    let cfg = HostConfig {
        data_dir: state.layout.content_webview.clone(),
        profile: "standard".into(),
        devtools,
        https_only,
        background: content_background(&handle, theme),
        network: state.network().proxy(),
        webrtc_proxy_only: {
            let store = state.store.lock().unwrap();
            let def = state.registry.get(untrace_webview::WEBRTC_ID).expect("protection def");
            state.registry.configured(&store, def) == untrace_core::registry::Value::Bool(true)
        },
    };
    let hwnd = win.hwnd()?;
    if let Some(e) = state.network().start_error() {
        // Fail closed: the user asked for the network layer, so no page opens without it.
        install_host(
            &handle,
            Err(format!(
                "{e} UNTRACE does not open pages without it. Set Encrypted DNS to Off in Settings, or restart UNTRACE."
            )),
        );
    } else if std::env::var_os("UNTRACE_EXPERIMENT_SHARED_ENV").is_some() {
        // EXPERIMENT (D-003): reuse the UI view's environment (created by Tauri).
        let app = handle.clone();
        let raw = hwnd.0 as isize;
        win.with_webview(move |pw| {
            let notify_app = app.clone();
            let notify: Notify = Rc::new(move |ev| on_host_event(&notify_app, ev));
            let parent = windows::Win32::Foundation::HWND(raw as *mut _);
            install_host(
                &app,
                ContentHost::with_environment(parent, cfg, notify, pw.environment()),
            );
        })?;
    } else {
        let notify_app = handle.clone();
        let notify: Notify = Rc::new(move |ev| on_host_event(&notify_app, ev));
        install_host(&handle, ContentHost::new(hwnd, cfg, notify));
    }
    match self_check {
        // The self-check never touches the network: no list updates.
        Some(out) => selfcheck::start(handle, out),
        None => {
            appupdate::start(handle.clone());
            filters::start_updater(handle)
        }
    }
    Ok(())
}

fn install_host(app: &AppHandle, result: Result<ContentHost, String>) {
    let state = app.state::<AppState>();
    match result {
        Ok(h) => {
            HOST.with(|x| *x.borrow_mut() = Some(h.clone()));
            let store = state.store.lock().unwrap();
            // Filters are in place before the first tab exists, so nothing loads unfiltered.
            let on = |id: &str| {
                state
                    .registry
                    .get(id)
                    .is_some_and(|d| state.registry.configured(&store, d) == Value::Bool(true))
            };
            state.filters.set_initial(
                untrace_filter::catalog()
                    .iter()
                    .filter(|l| on(l.protection))
                    .map(|l| l.id),
            );
            h.set_filters(state.filters.build());
            // D-053: what pages are told about light/dark, before the first profile exists.
            let follow = store.settings().pages_follow_theme;
            let _ = h.set_page_color_scheme(appearance::page_scheme(store.settings().theme, follow));
            h.set_site_exceptions(store.settings().filter_exceptions.iter().cloned());
            h.set_local_sites(store.settings().local_network_sites.iter().cloned());
            state.exit_clear.set_initial(
                on(privacy::CLEAR_CACHE_ON_EXIT_ID),
                on(privacy::CLEAR_SITE_DATA_ON_EXIT_ID),
            );
            // What the previous session should have cleared on exit and did not (crash, power
            // loss, Windows shutdown) is cleared before this session's first page loads.
            let owed = state.exit_clear.take_owed();
            if owed.any() {
                h.set_startup_clear(owed.clear_kinds());
                let _ = state.audit.record(AuditEvent::DataCleared {
                    what: "at start, because the last exit did not finish clearing".into(),
                    ok: true,
                });
            }
            let mut applier = filters::Applied {
                host: Some(h.clone()),
                filters: &state.filters,
                exit: &state.exit_clear,
                network: state.network(),
            };
            state.registry.apply_all(&store, &state.audit, &mut applier);
            drop(store);
            state.exit_clear.mark_pending();
            h.new_tab(None);
        }
        Err(e) => {
            let _ = state.audit.record(AuditEvent::Error {
                component: "engine".into(),
                message: e.clone(),
            });
            *state.host_error.lock().unwrap() = Some(e);
        }
    }
}

fn describe(o: &LoadOutcome) -> String {
    match o {
        LoadOutcome::Created => "created with defaults".into(),
        LoadOutcome::Loaded => "loaded".into(),
        LoadOutcome::Repaired { repairs } => format!("repaired: {}", repairs.join("; ")),
        LoadOutcome::Reset { reason, .. } => format!("reset to defaults: {reason}"),
    }
}

fn fatal(text: &str) -> ! {
    platform::message_box("UNTRACE", text);
    std::process::exit(1);
}

fn main() {
    if platform::is_elevated() {
        fatal("UNTRACE does not run with administrator rights. Please start it again as a normal user.");
    }
    let args: Vec<String> = std::env::args().collect();
    let self_check = args.iter().position(|a| a == "--self-check").map(|i| {
        PathBuf::from(
            args.get(i + 1)
                .cloned()
                .unwrap_or_else(|| "untrace-self-check.json".into()),
        )
    });

    // A self-check always runs in its own sub-folder, so it never touches a real profile.
    let root = if self_check.is_some() {
        paths::data_root().join("self-check")
    } else {
        paths::data_root()
    };
    if self_check.is_some() {
        let _ = std::fs::remove_dir_all(root.join("content"));
    }
    let layout = Layout::new(root);
    if let Err(e) = layout.create_all() {
        fatal(&format!("UNTRACE could not create its data folder: {e}"));
    }
    let audit = AuditLog::open(&layout.logs).unwrap_or_else(|e| fatal(&format!("UNTRACE could not open its log: {e}")));
    let _ = audit.record(AuditEvent::AppStarted {
        version: untrace_core::VERSION.into(),
    });
    let registry = Registry::new(protections::defs());
    let (store, outcome) = SettingsStore::open(&layout.config, registry.defs())
        .unwrap_or_else(|e| fatal(&format!("UNTRACE could not read or create its settings: {e}")));
    let _ = audit.record(AuditEvent::ConfigLoaded {
        outcome: describe(&outcome),
    });
    let filters = filters::FilterService::open(&layout.root.join("filters"))
        .unwrap_or_else(|e| fatal(&format!("UNTRACE could not open its block-list folder: {e}")));
    let exit_clear = privacy::ExitClear::open(layout.config.join("exit-clear.json"));
    let app_updates = appupdate::AppUpdates::open(layout.config.join("app-update.json"));

    let state = AppState {
        store: Mutex::new(store),
        audit,
        registry,
        layout,
        config_status: outcome,
        content_dip: Mutex::new(None),
        host_error: Mutex::new(None),
        main_thread: std::thread::current().id(),
        filters,
        exit_clear,
        engine_scrub: Mutex::new(None),
        network: std::sync::OnceLock::new(),
        selftest: selftest::SelfTest::default(),
        self_check: self_check.is_some(),
        app_updates,
    };

    // M9 (D-016): the official updater; it verifies every download's signature.
    let mut builder = tauri::Builder::default().plugin(tauri_plugin_updater::Builder::new().build());
    if self_check.is_none() {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }));
    }
    builder
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::ui_ready,
            commands::tab_new,
            commands::tab_close,
            commands::tab_activate,
            commands::tab_cycle,
            commands::navigate,
            commands::go_back,
            commands::go_forward,
            commands::reload,
            commands::stop,
            commands::set_content_bounds,
            commands::focus_content,
            commands::settings_get,
            commands::protection_set,
            commands::theme_set,
            commands::accent_set,
            commands::welcome_done,
            commands::about_get,
            commands::notices_get,
            commands::app_update_status,
            commands::app_update_check,
            commands::app_update_install,
            commands::pages_theme_set,
            commands::search_set,
            commands::diagnostics_get,
            commands::audit_clear,
            commands::interstitial_action,
            commands::notice_dismiss,
            commands::prompt_respond,
            commands::permission_reset,
            commands::download_show,
            commands::download_cancel,
            commands::downloads_clear,
            commands::site_filtering_set,
            commands::filters_update_now,
            commands::tab_new_temporary,
            commands::cookie_sites,
            commands::site_data_delete,
            commands::data_inventory,
            commands::data_clear,
            commands::site_local_set,
            commands::doh_custom_set,
            commands::network_records_clear,
            commands::selftest_start,
            commands::selftest_last,
            commands::audit_entries,
            commands::audit_export,
            commands::report_save,
        ])
        .setup(move |app| setup(app, self_check.clone()))
        .on_window_event(|w, e| match e {
            WindowEvent::ScaleFactorChanged { .. } | WindowEvent::Resized(_) => apply_bounds(w.app_handle()),
            WindowEvent::CloseRequested { api, .. } => {
                // "Delete … when UNTRACE closes": the window hides, the engine clears, and the
                // window is destroyed when it has finished.
                if privacy::begin_exit_clear(w.app_handle()) {
                    api.prevent_close();
                }
            }
            WindowEvent::Destroyed => {
                // Release the content host now. Left in the thread-local, it would be dropped
                // inside ExitProcess, where WebView2 blocks forever (found in M2: the process
                // hung on close with one thread in EmbeddedBrowserWebView).
                if let Some(h) = HOST.with(|x| x.borrow_mut().take()) {
                    h.shutdown();
                }
            }
            _ => {}
        })
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| fatal(&format!("UNTRACE failed to start: {e}")));
}
