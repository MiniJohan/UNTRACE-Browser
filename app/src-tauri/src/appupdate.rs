//! M9 (D-016): UNTRACE's own updates, through Tauri's updater.
//!
//! Once a day, while "Check for UNTRACE updates" is on, UNTRACE fetches the release manifest
//! (`latest.json` on GitHub Releases). An update is shown, never installed by itself. When the
//! user installs it, the installer is downloaded and verified against UNTRACE's Ed25519 public
//! key, including the version the signature was made for (`requireSignedVersion`, so an old
//! signed release cannot be passed off as a new one), and only then run.
//!
//! The release address and public key are part of `tauri.conf.json` (`plugins.updater`). A build
//! without them, such as a development build, never checks and says so.

use std::{
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};
use untrace_core::{
    audit::AuditEvent,
    registry::{Observed, Value},
};

use crate::AppState;

pub const AUTO_CHECK_ID: &str = "app.check_updates";
const EVERY: Duration = Duration::from_secs(24 * 3600);

/// The switch, as applied (Settings writes it through the registry; the worker reads it).
static ENABLED: AtomicBool = AtomicBool::new(true);
/// Whether this build has a release address and key (read once at start).
static CONFIGURED: AtomicBool = AtomicBool::new(false);

/// Called once at start, before Settings can ask.
pub fn init(app: &AppHandle) {
    CONFIGURED.store(configured(app), Ordering::SeqCst);
}

pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::SeqCst);
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::SeqCst)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Available {
    pub version: String,
    pub notes: Option<String>,
    pub date: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    pub current_version: String,
    /// The build knows where to look and which key to trust.
    pub configured: bool,
    pub enabled: bool,
    pub checking: bool,
    pub installing: bool,
    /// Seconds since 1970 of the last finished check (kept across restarts).
    pub last_check: Option<u64>,
    /// "up to date", "update available" or what went wrong.
    pub last_result: Option<String>,
    pub available: Option<Available>,
}

pub struct AppUpdates {
    status: Mutex<UpdateStatus>,
    pending: Mutex<Option<Update>>,
    attempts: AtomicUsize,
    file: PathBuf,
}

/// Is the build set up for updates (release address and public key in its configuration)?
pub fn configured(app: &AppHandle) -> bool {
    let cfg = app.config();
    let u = cfg.plugins.0.get("updater");
    let key = u
        .and_then(|u| u["pubkey"].as_str())
        .is_some_and(|k| !k.trim().is_empty());
    let endpoints = u.and_then(|u| u["endpoints"].as_array()).is_some_and(|e| !e.is_empty());
    key && endpoints
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl AppUpdates {
    pub fn open(file: PathBuf) -> Self {
        let last_check = std::fs::read(&file)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v["lastCheck"].as_u64());
        Self {
            status: Mutex::new(UpdateStatus {
                current_version: untrace_core::VERSION.into(),
                last_check,
                ..Default::default()
            }),
            pending: Mutex::new(None),
            attempts: AtomicUsize::new(0),
            file,
        }
    }

    pub fn status(&self, app: &AppHandle) -> UpdateStatus {
        let mut s = self.status.lock().unwrap().clone();
        s.configured = configured(app);
        s.enabled = enabled();
        s
    }

    /// Checks started (self-check: none while the switch is off).
    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }

    fn due(&self) -> bool {
        let last = self.status.lock().unwrap().last_check;
        last.is_none_or(|t| now().saturating_sub(t) >= EVERY.as_secs())
    }
}

/// Settings read-back.
pub fn observe() -> Observed {
    if !CONFIGURED.load(Ordering::SeqCst) {
        return Observed::Unverifiable(
            "This build has no release address or update key, so it never checks (a development or test build).".into(),
        );
    }
    // UNTRACE's own update worker reads this flag before every check.
    Observed::Verified(Value::Bool(enabled()))
}

fn emit(app: &AppHandle) {
    let state = app.state::<AppState>();
    let _ = app.emit_to("main", "app-update", state.app_updates.status(app));
}

/// Ask the release address whether a newer version exists. Shows it; installs nothing.
pub async fn check(app: AppHandle) -> Result<Option<Available>, String> {
    let state = app.state::<AppState>();
    if !configured(&app) {
        return Err("This build has no release address or update key.".into());
    }
    {
        let mut s = state.app_updates.status.lock().unwrap();
        if s.checking || s.installing {
            return Err("UNTRACE is already checking or installing.".into());
        }
        s.checking = true;
    }
    state.app_updates.attempts.fetch_add(1, Ordering::SeqCst);
    emit(&app);
    let result = match app.updater() {
        Ok(u) => u.check().await.map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    let available = match &result {
        Ok(Some(u)) => Some(Available {
            version: u.version.clone(),
            notes: u.body.clone(),
            date: u.date.map(|d| d.to_string()),
        }),
        _ => None,
    };
    let text = match &result {
        Ok(Some(u)) => format!("UNTRACE {} is available", u.version),
        Ok(None) => "up to date".into(),
        Err(e) => format!("the check failed ({e})"),
    };
    {
        let mut s = state.app_updates.status.lock().unwrap();
        s.checking = false;
        s.last_check = Some(now());
        s.last_result = Some(text.clone());
        s.available = available.clone();
    }
    *state.app_updates.pending.lock().unwrap() = result.as_ref().ok().cloned().flatten();
    let _ = std::fs::write(
        &state.app_updates.file,
        serde_json::json!({ "lastCheck": now() }).to_string(),
    );
    let _ = state.audit.record(AuditEvent::AppUpdate { result: text });
    emit(&app);
    result.map(|_| available)
}

/// Download, verify and run the update the last check found. On success the installer takes
/// over and UNTRACE exits (the cache is then cleared at the next start, D-038).
pub async fn install(app: AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    let Some(update) = state.app_updates.pending.lock().unwrap().clone() else {
        return Err("No update is waiting; check first.".into());
    };
    state.app_updates.status.lock().unwrap().installing = true;
    emit(&app);
    let version = update.version.clone();
    // `download` verifies the signature and the signed version before returning the bytes;
    // `install` verifies them again before it runs anything.
    let result = match update.download(|_, _| {}, || {}).await {
        Ok(bytes) => {
            let _ = state.audit.record(AuditEvent::AppUpdate {
                result: format!("UNTRACE {version} downloaded and verified; installing"),
            });
            update.install(bytes).map_err(|e| e.to_string())
        }
        Err(e) => Err(e.to_string()),
    };
    if let Err(e) = &result {
        state.app_updates.status.lock().unwrap().installing = false;
        state.app_updates.status.lock().unwrap().last_result = Some(format!("installing failed ({e})"));
        let _ = state.audit.record(AuditEvent::AppUpdate {
            result: format!("UNTRACE {version} was not installed ({e})"),
        });
        emit(&app);
    }
    result
}

/// One round of the daily worker. True if it started a check. With the switch off it does not
/// even look (self-check).
pub fn tick(app: &AppHandle) -> bool {
    let state = app.state::<AppState>();
    if !enabled() || !configured(app) || !state.app_updates.due() {
        return false;
    }
    let _ = tauri::async_runtime::block_on(check(app.clone()));
    true
}

/// The daily worker: first look two minutes after start, then every 30 minutes whether a day
/// has passed since the last check.
pub fn start(app: AppHandle) {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(120));
        loop {
            tick(&app);
            thread::sleep(Duration::from_secs(30 * 60));
        }
    });
}
