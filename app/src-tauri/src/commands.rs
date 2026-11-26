//! IPC commands for the UNTRACE interface. Granted to the `main` window only
//! (capabilities/main.json). Every argument is validated here, in Rust.
//!
//! Commands are synchronous, so Tauri runs them on the UI thread — the only thread that may
//! touch WebView2. `on_ui_thread` turns a violation of that assumption into an error.

use serde::Serialize;
use tauri::{AppHandle, Manager, State, WebviewWindow};
use untrace_core::audit::AuditEvent;
use untrace_core::{
    address::{self, SearchEngine},
    policy::Permission,
    registry::{ChangeOutcome, ProtectionStatus, Value},
    settings::{Accent, AccentColors, MAX_FILTER_EXCEPTIONS, Theme, is_site_name},
    store::LoadOutcome,
};
use untrace_webview::{ClearKinds, ContentHost, CookieSite, EngineInfo, NetworkCheck, ScrubReport, Snapshot};

use crate::{
    AppState, ContentRect, UI_NAV_BLOCKED, apply_bounds,
    filters::{Applied, ListStatus},
    host,
    privacy::{self, DataItem, EngineFacts, ExitRecord, with_host},
};

pub(crate) type R<T> = Result<T, String>;

pub(crate) fn on_ui_thread(state: &AppState) -> R<()> {
    if std::thread::current().id() == state.main_thread {
        Ok(())
    } else {
        Err("internal error: command ran off the UI thread".into())
    }
}

fn engine(state: &AppState) -> R<ContentHost> {
    on_ui_thread(state)?;
    host().ok_or_else(|| {
        state
            .host_error
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "The browser engine is not running.".into())
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineOption {
    id: SearchEngine,
    label: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    theme: Theme,
    /// D-053: accent colour, the presets with their colours, and what pages are told.
    accent: Accent,
    accents: Vec<AccentOption>,
    pages_follow_theme: bool,
    /// Read back from the engine's profiles (`None` before a tab has started).
    pages_scheme: Option<untrace_webview::PageColorScheme>,
    pages_scheme_error: Option<String>,
    search_engine: SearchEngine,
    custom_template: Option<String>,
    /// The user's own DNS-over-HTTPS server for Strict, if saved.
    custom_doh: Option<untrace_core::settings::CustomDoh>,
    /// M7: the last self-check's result per protection (`{ state, at, failed }`).
    self_tests: std::collections::BTreeMap<String, serde_json::Value>,
    engines: Vec<EngineOption>,
    protections: Vec<ProtectionStatus>,
    config_status: LoadOutcome,
}

fn settings_view(state: &AppState) -> SettingsView {
    let store = state.store.lock().unwrap();
    // Without an engine, the applier reports every protection as unverifiable.
    let applier = Applied {
        host: host(),
        filters: &state.filters,
        exit: &state.exit_clear,
        network: state.network(),
    };
    let protections = state.registry.status(&store, &applier);
    let s = store.settings();
    let scheme = host().and_then(|h| h.page_color_scheme());
    SettingsView {
        self_tests: state.selftest.by_protection(),
        custom_doh: s.custom_doh.clone(),
        theme: s.theme,
        accent: s.accent,
        accents: Accent::ALL
            .iter()
            .map(|a| AccentOption {
                id: *a,
                label: a.label(),
                colors: a.colors(),
            })
            .collect(),
        pages_follow_theme: s.pages_follow_theme,
        pages_scheme: scheme.as_ref().and_then(|r| r.as_ref().ok().copied()),
        pages_scheme_error: scheme.and_then(|r| r.err()),
        search_engine: s.search.engine,
        custom_template: s.search.custom_template.clone(),
        engines: SearchEngine::ALL
            .iter()
            .map(|e| EngineOption {
                id: *e,
                label: e.label(),
            })
            .collect(),
        protections,
        config_status: state.config_status.clone(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bootstrap {
    snapshot: Snapshot,
    settings: SettingsView,
    host_error: Option<String>,
    /// M9: show the one-screen welcome (first start; never in the self-check).
    show_welcome: bool,
}

#[tauri::command]
pub fn ui_ready(state: State<AppState>, window: WebviewWindow) -> R<Bootstrap> {
    on_ui_thread(&state)?;
    let _ = window.show();
    let _ = window.set_focus();
    Ok(Bootstrap {
        snapshot: host().map(|h| h.snapshot()).unwrap_or_default(),
        settings: settings_view(&state),
        host_error: state.host_error.lock().unwrap().clone(),
        show_welcome: !state.self_check && !state.store.lock().unwrap().settings().welcome_seen,
    })
}

/// M9: the welcome screen was closed; it is not shown again.
#[tauri::command]
pub fn welcome_done(state: State<AppState>) -> R<()> {
    on_ui_thread(&state)?;
    state
        .store
        .lock()
        .unwrap()
        .update(|s| s.welcome_seen = true)
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct About {
    version: &'static str,
    runtime_version: Option<String>,
    licence: &'static str,
    licence_text: &'static str,
    /// PRIVACY.md, compiled in: the app and the repository show the same notice.
    privacy: &'static str,
}

/// M9: the About page: version, licence and privacy notice.
#[tauri::command]
pub fn about_get(state: State<AppState>) -> R<About> {
    on_ui_thread(&state)?;
    Ok(About {
        version: untrace_core::VERSION,
        runtime_version: host().and_then(|h| h.engine_info().runtime_version),
        licence: "MPL-2.0",
        licence_text: include_str!("../../../LICENSE"),
        privacy: include_str!("../../../PRIVACY.md"),
    })
}

/// M9: UNTRACE's own updates (D-016).
#[tauri::command]
pub fn app_update_status(app: AppHandle, state: State<AppState>) -> R<crate::appupdate::UpdateStatus> {
    on_ui_thread(&state)?;
    Ok(state.app_updates.status(&app))
}

/// Check now (Diagnostics › Updates); the result also arrives as an `app-update` event.
#[tauri::command]
pub async fn app_update_check(app: AppHandle) -> R<Option<crate::appupdate::Available>> {
    crate::appupdate::check(app).await
}

/// Download, verify and install the update found by the last check. UNTRACE exits when the
/// installer starts.
#[tauri::command]
pub async fn app_update_install(app: AppHandle) -> R<()> {
    crate::appupdate::install(app).await
}

/// M9: the licences of the third-party software in UNTRACE (generated by scripts/notices).
#[tauri::command]
pub fn notices_get(state: State<AppState>) -> R<&'static str> {
    on_ui_thread(&state)?;
    Ok(include_str!("../THIRD-PARTY-NOTICES.txt"))
}

#[tauri::command]
pub fn tab_new(state: State<AppState>) -> R<u32> {
    Ok(engine(&state)?.new_tab(None))
}

/// A temporary tab (Ctrl+Shift+N): its cookies, storage, cache and history are discarded when
/// the last temporary tab closes.
#[tauri::command]
pub fn tab_new_temporary(state: State<AppState>) -> R<u32> {
    Ok(engine(&state)?.new_temporary_tab(None))
}

#[tauri::command]
pub fn tab_close(state: State<AppState>, id: u32) -> R<()> {
    engine(&state)?.close_tab(id);
    Ok(())
}

#[tauri::command]
pub fn tab_activate(state: State<AppState>, id: u32) -> R<()> {
    engine(&state)?.activate(id);
    Ok(())
}

#[tauri::command]
pub fn tab_cycle(state: State<AppState>, forward: bool) -> R<()> {
    engine(&state)?.cycle(forward);
    Ok(())
}

/// Address-field input. Resolution (URL vs. search, refused schemes) happens in Rust.
#[tauri::command]
pub fn navigate(state: State<AppState>, input: String) -> R<()> {
    let h = engine(&state)?;
    let search = state.store.lock().unwrap().settings().search.clone();
    let target =
        address::resolve(&input, search.engine, search.custom_template.as_deref()).map_err(|e| e.to_string())?;
    h.navigate_active(target.url().as_str());
    Ok(())
}

#[tauri::command]
pub fn go_back(state: State<AppState>) -> R<()> {
    engine(&state)?.back();
    Ok(())
}

#[tauri::command]
pub fn go_forward(state: State<AppState>) -> R<()> {
    engine(&state)?.forward();
    Ok(())
}

#[tauri::command]
pub fn reload(state: State<AppState>) -> R<()> {
    engine(&state)?.reload();
    Ok(())
}

#[tauri::command]
pub fn stop(state: State<AppState>) -> R<()> {
    engine(&state)?.stop();
    Ok(())
}

#[tauri::command]
pub fn set_content_bounds(
    app: AppHandle,
    state: State<AppState>,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    visible: bool,
) -> R<()> {
    on_ui_thread(&state)?;
    let sane = |v: f64| v.is_finite() && (0.0..=100_000.0).contains(&v);
    if ![x, y, width, height].iter().all(|v| sane(*v)) {
        return Err("invalid content bounds".into());
    }
    *state.content_dip.lock().unwrap() = Some(ContentRect {
        x,
        y,
        w: width,
        h: height,
        visible,
    });
    apply_bounds(&app);
    Ok(())
}

#[tauri::command]
pub fn focus_content(state: State<AppState>) -> R<()> {
    engine(&state)?.focus_active();
    Ok(())
}

#[tauri::command]
pub fn settings_get(state: State<AppState>) -> R<SettingsView> {
    on_ui_thread(&state)?;
    Ok(settings_view(&state))
}

#[tauri::command]
pub fn protection_set(state: State<AppState>, id: String, value: Value) -> R<ChangeOutcome> {
    let h = engine(&state)?;
    if id.len() > 100 {
        return Err("invalid protection id".into());
    }
    let mut store = state.store.lock().unwrap();
    let mut applier = Applied {
        host: Some(h),
        filters: &state.filters,
        exit: &state.exit_clear,
        network: state.network(),
    };
    Ok(state
        .registry
        .change(&id, value, &mut store, &state.audit, &mut applier))
}

/// A registrable domain exactly as the content host reports it for a tab.
fn site_name(site: &str) -> R<String> {
    let site = site.trim().to_ascii_lowercase();
    let canonical = untrace_filter::registrable_domain(&format!("https://{site}/"));
    if !is_site_name(&site) || canonical.as_deref() != Some(site.as_str()) {
        return Err("not a site name".into());
    }
    Ok(site)
}

/// Turn ads/trackers blocking off (or back on) for one site. Saved in Settings, except from a
/// temporary tab, where it lasts only until the temporary session ends.
#[tauri::command]
pub fn site_filtering_set(state: State<AppState>, site: String, on: bool, temporary: Option<bool>) -> R<()> {
    let h = engine(&state)?;
    let site = site_name(&site)?;
    if temporary == Some(true) {
        h.set_temp_site_filtering(&site, on);
        return Ok(());
    }
    let mut store = state.store.lock().unwrap();
    let mut list = store.settings().filter_exceptions.clone();
    list.retain(|s| s != &site);
    if !on {
        if list.len() >= MAX_FILTER_EXCEPTIONS {
            return Err(format!("at most {MAX_FILTER_EXCEPTIONS} sites can be excluded"));
        }
        list.push(site);
        list.sort();
    }
    store
        .update(|s| s.filter_exceptions = list.clone())
        .map_err(|e| e.to_string())?;
    drop(store);
    h.set_site_exceptions(list);
    Ok(())
}

/// D-040: allow (or stop allowing) a site to reach this computer and the local network.
/// Saved in Settings, or for temporary tabs kept until the temporary session ends.
#[tauri::command]
pub fn site_local_set(state: State<AppState>, site: String, allowed: bool, temporary: Option<bool>) -> R<()> {
    let h = engine(&state)?;
    let site = site_name(&site)?;
    if temporary == Some(true) {
        h.set_temp_site_local(&site, allowed);
        return Ok(());
    }
    let mut store = state.store.lock().unwrap();
    let mut list = store.settings().local_network_sites.clone();
    list.retain(|s| s != &site);
    if allowed {
        if list.len() >= MAX_FILTER_EXCEPTIONS {
            return Err(format!("at most {MAX_FILTER_EXCEPTIONS} sites can be allowed"));
        }
        list.push(site);
        list.sort();
    }
    store
        .update(|s| s.local_network_sites = list.clone())
        .map_err(|e| e.to_string())?;
    drop(store);
    let _ = state.audit.record(AuditEvent::SettingChanged {
        id: "security.local_network.sites".into(),
        from: String::new(),
        to: format!(
            "{} site(s) allowed",
            h.snapshot().local_network_sites.len() + usize::from(allowed)
        ),
        verified: true,
    });
    h.set_local_sites(list);
    Ok(())
}

/// Save the user's own DNS-over-HTTPS server for Strict (D-041). Checked before it is saved.
#[tauri::command]
pub fn doh_custom_set(state: State<AppState>, template: String, address: String) -> R<SettingsView> {
    on_ui_thread(&state)?;
    let server = untrace_net::resolver::custom_server(&template, &address)?;
    let saved = untrace_core::settings::CustomDoh {
        template: server.template.clone(),
        address: server.address.to_string(),
    };
    state
        .store
        .lock()
        .unwrap()
        .update(|s| s.custom_doh = Some(saved.clone()))
        .map_err(|e| e.to_string())?;
    state.network().set_custom(Some(server));
    let _ = state.audit.record(AuditEvent::SettingChanged {
        id: "network.doh_custom".into(),
        from: String::new(),
        to: "a custom server".into(),
        verified: true,
    });
    Ok(settings_view(&state))
}

/// Forget the network layer's connection record and cached DNS answers (memory only).
#[tauri::command]
pub fn network_records_clear(state: State<AppState>) -> R<()> {
    on_ui_thread(&state)?;
    if let Some(p) = state.network().proxy() {
        p.clear_records();
    }
    let _ = state.audit.record(AuditEvent::DataCleared {
        what: "network layer connection record and DNS cache".into(),
        ok: true,
    });
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccentOption {
    id: Accent,
    label: &'static str,
    colors: Option<AccentColors>,
}

/// Apply the saved look to the engine; a failure is reported, the setting stays saved.
fn apply_appearance(app: &AppHandle) -> R<()> {
    crate::appearance::apply_frame(app);
    match host() {
        Some(h) => crate::appearance::apply(app, &h).map_err(|e| format!("Saved, but the engine refused it ({e}).")),
        None => Ok(()),
    }
}

#[tauri::command]
pub fn theme_set(app: AppHandle, state: State<AppState>, theme: Theme) -> R<SettingsView> {
    on_ui_thread(&state)?;
    state
        .store
        .lock()
        .unwrap()
        .update(|s| s.theme = theme)
        .map_err(|e| e.to_string())?;
    apply_appearance(&app)?;
    Ok(settings_view(&state))
}

/// D-053: the interface's accent colour (UNTRACE's own window only; pages never see it).
#[tauri::command]
pub fn accent_set(state: State<AppState>, accent: Accent) -> R<SettingsView> {
    on_ui_thread(&state)?;
    state
        .store
        .lock()
        .unwrap()
        .update(|s| s.accent = accent)
        .map_err(|e| e.to_string())?;
    Ok(settings_view(&state))
}

/// D-053: tell websites UNTRACE's light/dark choice, or let them follow Windows.
#[tauri::command]
pub fn pages_theme_set(app: AppHandle, state: State<AppState>, on: bool) -> R<SettingsView> {
    on_ui_thread(&state)?;
    state
        .store
        .lock()
        .unwrap()
        .update(|s| s.pages_follow_theme = on)
        .map_err(|e| e.to_string())?;
    apply_appearance(&app)?;
    Ok(settings_view(&state))
}

#[tauri::command]
pub fn search_set(state: State<AppState>, engine: SearchEngine, custom_template: Option<String>) -> R<SettingsView> {
    on_ui_thread(&state)?;
    let custom = match engine {
        SearchEngine::Custom => {
            let t = custom_template.ok_or("Enter a search address containing {q}.")?;
            address::validate_template(&t).map_err(|e| e.to_string())?;
            Some(t)
        }
        _ => None,
    };
    state
        .store
        .lock()
        .unwrap()
        .update(|s| {
            s.search.engine = engine;
            s.search.custom_template = custom;
        })
        .map_err(|e| e.to_string())?;
    Ok(settings_view(&state))
}

/// Act on UNTRACE's own panel: "back", "retry", "continue_http" or "continue_threat" (each only
/// where that panel offers it; the content host checks).
#[tauri::command]
pub fn interstitial_action(state: State<AppState>, id: u32, action: String) -> R<()> {
    engine(&state)?.interstitial_action(id, &action)
}

#[tauri::command]
pub fn notice_dismiss(state: State<AppState>, id: u32) -> R<()> {
    engine(&state)?.dismiss_notice(id);
    Ok(())
}

/// Answer a permission, external-application or download question.
#[tauri::command]
pub fn prompt_respond(state: State<AppState>, id: u32, allow: bool, remember: bool) -> R<()> {
    engine(&state)?.respond(id, allow, remember)
}

#[tauri::command]
pub fn permission_reset(state: State<AppState>, origin: String, permission: Permission) -> R<()> {
    let h = engine(&state)?;
    let o = url::Url::parse(&origin).map_err(|_| "invalid site")?;
    if !matches!(o.scheme(), "http" | "https") || o.host_str().is_none() {
        return Err("invalid site".into());
    }
    h.reset_permission(&o.origin().ascii_serialization(), permission)
}

#[tauri::command]
pub fn download_show(state: State<AppState>, id: u32) -> R<()> {
    engine(&state)?.show_download(id)
}

#[tauri::command]
pub fn download_cancel(state: State<AppState>, id: u32) -> R<()> {
    engine(&state)?.cancel_download(id);
    Ok(())
}

#[tauri::command]
pub fn downloads_clear(state: State<AppState>) -> R<()> {
    engine(&state)?.clear_downloads();
    Ok(())
}

fn engine_clear(app: &AppHandle, kinds: ClearKinds) -> R<()> {
    with_host(app, move |h, tx| {
        let tx2 = tx.clone();
        if !h.clear_data(kinds, move |r| {
            let _ = tx.send(r);
        }) {
            let _ = tx2.send(Err("No normal tab is open; open one and try again.".into()));
        }
    })?
}

fn cookies_left(app: &AppHandle) -> R<u32> {
    let sites = with_host(app, |h, tx| {
        h.cookie_sites(move |r| {
            let _ = tx.send(r);
        })
    })??;
    Ok(sites.iter().map(|s| s.cookies).sum())
}

/// Sites with cookies in normal tabs (read from the engine).
#[tauri::command]
pub async fn cookie_sites(app: AppHandle) -> R<Vec<CookieSite>> {
    tauri::async_runtime::spawn_blocking(move || {
        with_host(&app, |h, tx| {
            h.cookie_sites(move |r| {
                let _ = tx.send(r);
            })
        })
    })
    .await
    .map_err(|e| e.to_string())??
}

/// Delete one site's cookies and stored data from normal tabs. Returns how many of its cookies
/// are left afterwards (read back; 0 when it worked). The log records that a site's data was
/// deleted, never which site.
#[tauri::command]
pub async fn site_data_delete(app: AppHandle, site: String) -> R<u32> {
    let site = site_name(&site)?;
    let a = app.clone();
    let left = tauri::async_runtime::spawn_blocking(move || {
        with_host(&a, move |h, tx| {
            h.delete_site_data(&site, move |r| {
                let _ = tx.send(r);
            })
        })
    })
    .await
    .map_err(|e| e.to_string())???;
    let _ = app.state::<AppState>().audit.record(AuditEvent::DataCleared {
        what: "cookies and site data of one site".into(),
        ok: left == 0,
    });
    Ok(left)
}

/// What UNTRACE and its engine keep, where, how much and for how long.
#[tauri::command]
pub async fn data_inventory(app: AppHandle) -> R<Vec<DataItem>> {
    let a = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let facts = with_host(&a, |h, tx| {
            let snap = h.snapshot();
            let base = EngineFacts {
                cookies: None,
                saved_permissions: snap.stored_permissions.len(),
                temporary_tabs: snap.tabs.iter().filter(|t| t.temporary).count(),
                downloads: snap.downloads.len(),
            };
            h.cookie_sites(move |r| {
                let _ = tx.send(EngineFacts {
                    cookies: Some(r.map(|s| (s.len(), s.iter().map(|c| c.cookies).sum()))),
                    ..base
                });
            });
        })
        .unwrap_or_default();
        privacy::inventory(&a.state::<AppState>(), &facts)
    })
    .await
    .map_err(|e| e.to_string())
}

/// Delete one category of the data inventory now. Returns a sentence saying what was done and
/// how it was checked.
#[tauri::command]
pub async fn data_clear(app: AppHandle, id: String) -> R<String> {
    let a = app.clone();
    tauri::async_runtime::spawn_blocking(move || clear_category(&a, &id))
        .await
        .map_err(|e| e.to_string())?
}

fn clear_category(app: &AppHandle, id: &str) -> R<String> {
    let state = app.state::<AppState>();
    let (what, result): (&str, R<String>) = match id {
        "site_data" => {
            let r = engine_clear(
                app,
                ClearKinds {
                    site_data: true,
                    ..Default::default()
                },
            )
            .and_then(|_| cookies_left(app))
            .and_then(|left| match left {
                0 => Ok("Deleted. The engine reports no cookies left.".to_string()),
                n => Err(format!("The engine still reports {n} cookie(s).")),
            });
            ("all cookies and site data", r)
        }
        "cache" => {
            let r = engine_clear(
                app,
                ClearKinds {
                    cache: true,
                    ..Default::default()
                },
            )
            .map(|_| "Deleted.".to_string());
            ("cache", r)
        }
        "history" => {
            let r = engine_clear(
                app,
                ClearKinds {
                    history: true,
                    ..Default::default()
                },
            )
            .map(|_| "Deleted.".to_string());
            ("engine browsing history", r)
        }
        "permissions" => {
            let r = with_host(app, |h, tx| {
                let perms = h.snapshot().stored_permissions;
                let n = perms.len();
                let failed = perms
                    .iter()
                    .filter(|p| h.reset_permission(&p.origin, p.permission).is_err())
                    .count();
                let _ = tx.send(if failed == 0 {
                    Ok(format!("{n} decision(s) reset."))
                } else {
                    Err(format!("{failed} of {n} could not be reset."))
                });
            })
            .and_then(|r| r);
            ("saved permission decisions", r)
        }
        "settings" => {
            let r = state
                .store
                .lock()
                .unwrap()
                .update(|s| s.filter_exceptions.clear())
                .map_err(|e| e.to_string())
                .and_then(|_| {
                    with_host(app, |h, tx| {
                        h.set_site_exceptions(Vec::<String>::new());
                        let _ = tx.send(());
                    })
                })
                .map(|_| "Forgotten. Blocking is on for every site again.".to_string());
            ("blocking exceptions", r)
        }
        // The log records its own clearing.
        "audit" => {
            return state
                .audit
                .clear()
                .map(|_| "Cleared.".to_string())
                .map_err(|e| e.to_string());
        }
        "crash_reports" => {
            let n = privacy::prune_crash_reports(&privacy::crash_report_dirs(&state.layout), std::time::Duration::ZERO);
            ("crash reports", Ok(format!("{n} report(s) deleted.")))
        }
        "network" => {
            let r = match state.network().proxy() {
                Some(p) => {
                    p.clear_records();
                    let left = p.hosts().len() + p.resolver().cache_len();
                    if left == 0 {
                        Ok("Forgotten. The network layer reports no record and no cached name left.".to_string())
                    } else {
                        Err(format!("{left} entries came back (new connections since)."))
                    }
                }
                None => Ok("Nothing to forget: the network layer is off.".to_string()),
            };
            ("network layer connection record and DNS cache", r)
        }
        _ => return Err("unknown data category".into()),
    };
    let _ = state.audit.record(AuditEvent::DataCleared {
        what: what.into(),
        ok: result.is_ok(),
    });
    result
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub name: &'static str,
    /// `Some(true)` passed, `Some(false)` failed, `None` could not be verified.
    pub ok: Option<bool>,
    pub detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostics {
    app_version: &'static str,
    tauri_version: &'static str,
    engine: Option<EngineInfo>,
    host_error: Option<String>,
    data_root: String,
    data_root_overridden: bool,
    settings_file: String,
    config_status: LoadOutcome,
    audit_file: String,
    audit_bytes: u64,
    audit_tail: Vec<String>,
    ui_navigation_blocked: usize,
    checks: Vec<Check>,
    filter_lists: Vec<ListStatus>,
    /// Milliseconds the last filter build took, and whether the cached engine was used.
    filter_build_ms: Option<u128>,
    filter_build_cached: Option<bool>,
    /// What the previous session cleared on exit, and what this one cleared at start instead.
    last_exit_clear: Option<ExitRecord>,
    start_clear: Option<privacy::ExitKinds>,
    /// DNS on this computer and the M5 network layer.
    network: crate::network::NetworkReport,
}

pub fn checks(engine: Option<&EngineInfo>, config: &LoadOutcome, scrub: Option<&ScrubReport>) -> Vec<Check> {
    let flag = |v: Option<bool>, want: bool| v.map(|b| b == want);
    let mut out = vec![Check {
        name: "Running without administrator rights",
        ok: Some(!crate::platform::is_elevated()),
        detail: "UNTRACE refuses to start elevated.".into(),
    }];
    let config_ok = !matches!(config, LoadOutcome::Reset { .. });
    out.push(Check {
        name: "Settings file valid",
        ok: Some(config_ok),
        detail: match config {
            LoadOutcome::Reset { reason, .. } => format!("Reset to defaults at start: {reason}"),
            LoadOutcome::Repaired { repairs } => format!("Repaired at start: {}", repairs.join("; ")),
            _ => "Loaded and validated at start.".into(),
        },
    });
    match engine {
        None => out.push(Check {
            name: "Browser engine",
            ok: Some(false),
            detail: "Not running.".into(),
        }),
        Some(e) => {
            let major = e
                .runtime_version
                .as_deref()
                .and_then(|v| v.split('.').next()?.parse::<u32>().ok());
            out.push(Check {
                name: "Browser engine version supported",
                ok: major.map(|m| m >= e.minimum_runtime_major),
                detail: format!(
                    "WebView2 Runtime {} (needs {} or newer).",
                    e.runtime_version.as_deref().unwrap_or("unknown"),
                    e.minimum_runtime_major
                ),
            });
            out.push(Check {
                name: "Browser engine up to date",
                ok: Some(!e.update_available),
                detail: if e.update_available {
                    "Microsoft installed a newer WebView2 Runtime. Restart UNTRACE to start using it.".into()
                } else {
                    "No newer runtime is waiting. Microsoft updates it automatically.".into()
                },
            });
            out.push(Check {
                name: "HTTPS-only mode on",
                ok: Some(e.https_only),
                detail: if e.https_session_exceptions > 0 {
                    format!(
                        "{} site(s) allowed over plain HTTP for this session.",
                        e.https_session_exceptions
                    )
                } else {
                    "No exceptions this session.".into()
                },
            });
            out.push(Check {
                name: "Request filtering registered",
                ok: Some(e.request_filtering_registered),
                detail: match e.worker_requests_tab {
                    Some(t) if e.request_filtering_registered => format!(
                        "Every tab's requests are checked; worker requests arrive through tab {t}. {} worker request(s) blocked this session.",
                        e.worker_requests_blocked
                    ),
                    _ if e.request_filtering_registered => "Every tab's requests are checked.".into(),
                    _ => "The engine refused to let UNTRACE check requests on at least one tab.".into(),
                },
            });
            out.push(Check {
                name: "UNTRACE error pages in use",
                ok: flag(e.builtin_error_pages_enabled, false),
                detail: "The engine's own error pages (which can offer unsafe ways to continue) are turned off.".into(),
            });
            let bridge = match (e.web_messages_enabled, e.host_objects_allowed) {
                (Some(w), Some(h)) => Some(!w && !h),
                _ => None,
            };
            out.push(Check {
                name: "Content views have no host bridge",
                ok: bridge,
                detail: "Web messages and host objects disabled (read back from the engine).".into(),
            });
            let secrets = match (e.password_autosave_enabled, e.autofill_enabled) {
                (Some(p), Some(a)) => Some(!p && !a),
                _ => None,
            };
            out.push(Check {
                name: "Password saving and autofill off",
                ok: secrets,
                detail: "Read back from the engine.".into(),
            });
            out.push(Check {
                name: "SmartScreen off (default)",
                ok: flag(e.smartscreen_enabled, false),
                detail: "No visited-site information is sent to Microsoft Defender SmartScreen.".into(),
            });
            out.push(Check {
                name: "Crash reports stay on this device",
                ok: e.crash_reports_local,
                detail: match e.crash_reports_local {
                    Some(true) => format!(
                        "Set when UNTRACE starts the engine (WebView2 cannot report it back). Folder: {}",
                        e.crash_report_folder.as_deref().unwrap_or("not reported yet")
                    ),
                    _ => "The engine was started without local crash reporting: crash dumps may be sent to Microsoft."
                        .into(),
                },
            });
            out.push(Check {
                name: "Engine traffic goes through the network layer",
                ok: match &e.network_check {
                    Some(NetworkCheck::Passed { .. }) => Some(true),
                    Some(NetworkCheck::Failed { .. }) => Some(false),
                    _ => None,
                },
                detail: match &e.network_check {
                    Some(NetworkCheck::Passed { ms }) => format!(
                        "At start, a test request from the engine reached UNTRACE's proxy with this launch's credentials ({ms} ms). Engine arguments: {}",
                        e.browser_arguments
                    ),
                    Some(NetworkCheck::Failed { reason }) => format!("{reason} Encrypted DNS is not verified."),
                    Some(NetworkCheck::Off) => "Encrypted DNS is off: the engine connects and resolves names itself.".into(),
                    _ => "Not checked yet.".into(),
                },
            });
            out.push(Check {
                name: "Ad space hidden in every tab",
                ok: match (e.hide_elements, &e.cosmetic_rules) {
                    (false, _) => None,
                    (true, Some(_)) => Some(e.hide_elements_tabs >= e.open_tabs),
                    (true, None) => Some(false),
                },
                detail: match (&e.cosmetic_rules, e.hide_elements) {
                    (_, false) => "Hiding is switched off in Settings.".into(),
                    (Some(r), true) => format!(
                        "{} of {} tab(s) carry the hiding script ({} KB): {} generic rules ({} by class or id), {} rules for {} sites, {} exceptions. Not applied: {} extended rules, {} with actions. {} scriptlet rules run with uBlock Origin {}'s scriptlets, with their lists (D-057).",
                        e.hide_elements_tabs,
                        e.open_tabs,
                        e.hide_elements_script_bytes / 1024,
                        r.generic,
                        r.generic_by_class_or_id,
                        r.specific,
                        r.hosts,
                        r.exceptions,
                        r.procedural,
                        r.actions,
                        r.scriptlets,
                        untrace_filter::scriptlets::resources_version()
                    ),
                    (None, true) => "The block lists are not loaded.".into(),
                },
            });
            out.push(Check {
                name: "WebRTC kept inside the network layer",
                ok: match &e.webrtc_proxy_only {
                    None => None,
                    Some(Ok(on)) => Some(*on),
                    Some(Err(_)) => Some(false),
                },
                detail: match &e.webrtc_proxy_only {
                    None => "No network layer is running (Encrypted DNS is off): WebRTC connects directly.".into(),
                    Some(Ok(true)) => "Set in the engine's profile before it started: WebRTC only through the network layer, no direct UDP and no lookups outside it.".into(),
                    Some(Ok(false)) => "Turned off in Settings: WebRTC connects directly, around the network layer.".into(),
                    Some(Err(err)) => format!("UNTRACE could not set it in the engine's profile ({err})."),
                },
            });
            out.push(Check {
                name: "Local-network protection on",
                ok: Some(e.local_network_protection),
                detail: format!(
                    "Parts of public sites cannot reach this computer or your local network. {} worker request(s) blocked this session.",
                    e.local_network_worker_blocked
                ),
            });
            out.push(Check {
                name: "Browsing history cleared at start",
                ok: e.history_cleared_at_start,
                detail: "WebView2 keeps history on disk; UNTRACE clears it before each session.".into(),
            });
        }
    }
    if let Some(s) = scrub {
        out.push(Check {
            name: "Engine records of visited sites removed at start",
            ok: Some(s.verified),
            detail: if s.problems.is_empty() {
                format!(
                    "Before the engine started: {} site-engagement record(s) and {} temporary-profile entr{} removed, \
                     {} temporary folder(s) deleted; files read back clean.",
                    s.engagement_removed,
                    s.temp_profile_entries_removed,
                    if s.temp_profile_entries_removed == 1 {
                        "y"
                    } else {
                        "ies"
                    },
                    s.temp_folders_removed
                )
            } else {
                format!("Not done: {}", s.problems.join("; "))
            },
        });
    }
    out
}

#[tauri::command]
pub fn diagnostics_get(state: State<AppState>) -> R<Diagnostics> {
    on_ui_thread(&state)?;
    Ok(diagnostics(&state))
}

/// What Diagnostics shows (also the basis of the security report). UI thread only.
pub fn diagnostics(state: &AppState) -> Diagnostics {
    let engine = host().map(|h| h.engine_info());
    let store = state.store.lock().unwrap();
    Diagnostics {
        app_version: untrace_core::VERSION,
        tauri_version: tauri::VERSION,
        checks: checks(
            engine.as_ref(),
            &state.config_status,
            state.engine_scrub.lock().unwrap().as_ref(),
        ),
        engine,
        host_error: state.host_error.lock().unwrap().clone(),
        data_root: state.layout.root.display().to_string(),
        data_root_overridden: untrace_core::paths::data_root_overridden(),
        settings_file: store.path().display().to_string(),
        config_status: state.config_status.clone(),
        audit_file: state.audit.path().display().to_string(),
        audit_bytes: state.audit.total_bytes(),
        audit_tail: state.audit.tail(50),
        ui_navigation_blocked: UI_NAV_BLOCKED.load(std::sync::atomic::Ordering::SeqCst),
        filter_lists: state.filters.status(),
        filter_build_ms: state.filters.last_build().map(|b| b.0),
        filter_build_cached: state.filters.last_build().map(|b| b.1),
        last_exit_clear: state.exit_clear.previous().cloned(),
        start_clear: state.exit_clear.startup(),
        network: crate::network::report(
            state.network(),
            &state
                .registry
                .get(crate::network::DNS_MODE_ID)
                .map(|d| state.registry.configured(&store, d).to_string())
                .unwrap_or_default(),
            host().map(|h| h.network_check()),
        ),
    }
}

#[tauri::command]
pub fn audit_clear(state: State<AppState>) -> R<()> {
    on_ui_thread(&state)?;
    state.audit.clear().map_err(|e| e.to_string()) // records a `log_cleared` event itself
}

/// Check every enabled block list for a new version now (Diagnostics). Runs the download off the
/// UI thread; the new filters are swapped in on the UI thread afterwards.
#[tauri::command]
pub async fn filters_update_now(app: AppHandle) -> R<bool> {
    let a = app.clone();
    let changed = tauri::async_runtime::spawn_blocking(move || a.state::<AppState>().filters.update(true))
        .await
        .map_err(|e| e.to_string())??;
    if changed {
        crate::filters::reload_into_host(&app);
    }
    Ok(changed)
}

// ------------------------------------------------------------------ M7

/// Start the self-check in a separate test instance (its own window and data folder, offline).
#[tauri::command]
pub fn selftest_start(app: AppHandle) -> R<()> {
    crate::selftest::start(&app)
}

/// The last self-check: when, what passed, per protection; and whether one is running.
#[tauri::command]
pub fn selftest_last(state: State<AppState>) -> R<serde_json::Value> {
    let last = state.selftest.last();
    let checks: Vec<serde_json::Value> = last
        .as_ref()
        .and_then(|r| r["checks"].as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .map(|c| serde_json::json!({ "name": c["name"], "ok": c["ok"], "skipped": c["skipped"].as_bool().unwrap_or(false) }))
        .collect();
    Ok(serde_json::json!({
        "running": state.selftest.running(),
        "at": last.as_ref().map(|r| r["at"].clone()),
        "passed": last.as_ref().map(|r| r["passed"].clone()),
        "checks": checks,
        "protections": last.as_ref().map(|r| r["protections"].clone()),
    }))
}

/// Every entry of the activity log, oldest first.
#[tauri::command]
pub fn audit_entries(state: State<AppState>) -> R<Vec<String>> {
    Ok(state.audit.all())
}

pub(crate) fn owner(app: &AppHandle) -> windows::Win32::Foundation::HWND {
    app.get_webview_window("main")
        .and_then(|w| w.hwnd().ok())
        .unwrap_or_default()
}

pub(crate) fn today() -> String {
    untrace_core::time::now_rfc3339().chars().take(10).collect()
}

/// Save a copy of the activity log where the user chooses. Returns the file's path, or `None`
/// if they cancelled.
#[tauri::command]
pub fn audit_export(app: AppHandle, state: State<AppState>) -> R<Option<String>> {
    on_ui_thread(&state)?;
    let entries = state.audit.all();
    let Some(path) = untrace_webview::save_as(
        owner(&app),
        std::path::Path::new(&format!("untrace-activity-{}.log", today())),
    ) else {
        return Ok(None);
    };
    std::fs::write(&path, entries.join("\n") + "\n").map_err(|e| format!("The file could not be written ({e})."))?;
    let _ = state.audit.record(AuditEvent::LogExported { entries: entries.len() });
    Ok(Some(path.display().to_string()))
}

/// Build the security report and save it where the user chooses. Returns the file's path, or
/// `None` if they cancelled.
#[tauri::command]
pub fn report_save(app: AppHandle, state: State<AppState>) -> R<Option<String>> {
    on_ui_thread(&state)?;
    let diag = serde_json::to_value(diagnostics(&state)).map_err(|e| e.to_string())?;
    let protections = {
        let store = state.store.lock().unwrap();
        let applier = Applied {
            host: host(),
            filters: &state.filters,
            exit: &state.exit_clear,
            network: state.network(),
        };
        state.registry.status(&store, &applier)
    };
    let last = state.selftest.last();
    let html = crate::report::html(&crate::report::Inputs {
        generated_at: untrace_core::time::now_rfc3339(),
        diagnostics: &diag,
        protections: &protections,
        self_test: last.as_ref(),
        self_test_by_protection: &state.selftest.by_protection(),
        audit: &state.audit.all(),
    });
    let Some(path) = untrace_webview::save_as(
        owner(&app),
        std::path::Path::new(&format!("untrace-security-report-{}.html", today())),
    ) else {
        return Ok(None);
    };
    std::fs::write(&path, html).map_err(|e| format!("The report could not be written ({e})."))?;
    let _ = state.audit.record(AuditEvent::ReportSaved);
    Ok(Some(path.display().to_string()))
}
