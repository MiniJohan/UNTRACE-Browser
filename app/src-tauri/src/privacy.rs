//! M4 privacy controls owned by the application:
//! - clearing browsing data when UNTRACE closes, with a start-up fallback when that did not
//!   finish (crash, power loss, Windows shutdown);
//! - crash-report retention (D-013: deleted after 7 days);
//! - leftover temporary-profile folders (D-028);
//! - the data inventory: what UNTRACE and its engine keep, where, how much, for how long.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use untrace_core::audit::AuditEvent;
use untrace_webview::{ClearKinds, ContentHost};

use crate::{AppState, host};

pub const CLEAR_CACHE_ON_EXIT_ID: &str = "privacy.clear_cache_on_exit";
pub const CLEAR_SITE_DATA_ON_EXIT_ID: &str = "privacy.clear_site_data_on_exit";
/// How long closing may wait for the engine to finish clearing.
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
/// D-013: crash reports older than this are deleted at start-up.
pub const CRASH_REPORT_DAYS: u64 = 7;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitKinds {
    pub cache: bool,
    pub site_data: bool,
}

impl ExitKinds {
    pub fn any(self) -> bool {
        self.cache || self.site_data
    }

    pub fn clear_kinds(self) -> ClearKinds {
        ClearKinds {
            cache: self.cache,
            site_data: self.site_data,
            ..Default::default()
        }
    }

    fn describe(self) -> &'static str {
        match (self.cache, self.site_data) {
            (true, true) => "cache, cookies and site data",
            (true, false) => "cache",
            (false, true) => "cookies and site data",
            (false, false) => "nothing",
        }
    }
}

/// What happened to the clearing a session owed on exit. Stored next to the settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitRecord {
    /// "pending" while a session runs that will clear on exit; then "done", "failed" or
    /// "timed_out". Anything but "done" makes the next start clear first.
    pub state: String,
    pub kinds: ExitKinds,
    /// Seconds since the Unix epoch.
    pub at: u64,
    /// Cookies still present after clearing site data (read back from the engine).
    pub cookies_left: Option<u32>,
    pub detail: Option<String>,
}

pub struct ExitClear {
    path: PathBuf,
    cache: AtomicBool,
    site_data: AtomicBool,
    /// The previous session's record, read at start (Diagnostics shows it).
    previous: Option<ExitRecord>,
    /// Cleared before the first page because the previous session did not finish.
    startup: Mutex<Option<ExitKinds>>,
    closing: AtomicBool,
}

impl ExitClear {
    pub fn open(path: PathBuf) -> Self {
        let previous = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok());
        Self {
            path,
            cache: AtomicBool::new(false),
            site_data: AtomicBool::new(false),
            previous,
            startup: Mutex::new(None),
            closing: AtomicBool::new(false),
        }
    }

    pub fn set_initial(&self, cache: bool, site_data: bool) {
        self.cache.store(cache, Ordering::SeqCst);
        self.site_data.store(site_data, Ordering::SeqCst);
    }

    pub fn kinds(&self) -> ExitKinds {
        ExitKinds {
            cache: self.cache.load(Ordering::SeqCst),
            site_data: self.site_data.load(Ordering::SeqCst),
        }
    }

    pub fn previous(&self) -> Option<&ExitRecord> {
        self.previous.as_ref()
    }

    pub fn startup(&self) -> Option<ExitKinds> {
        *self.startup.lock().unwrap()
    }

    /// What the previous session owed and did not finish: cleared before this session's first
    /// page. Called once, at start-up.
    pub fn take_owed(&self) -> ExitKinds {
        let owed = match &self.previous {
            Some(r) if r.state != "done" && r.kinds.any() => r.kinds,
            _ => ExitKinds::default(),
        };
        if owed.any() {
            *self.startup.lock().unwrap() = Some(owed);
        }
        owed
    }

    /// Record that this session will clear on exit (so a crash is caught at the next start).
    pub fn mark_pending(&self) {
        let kinds = self.kinds();
        if kinds.any() {
            self.write("pending", kinds, None, None);
        } else {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    pub fn set(&self, id: &str, on: bool) -> Result<(), String> {
        match id {
            CLEAR_CACHE_ON_EXIT_ID => self.cache.store(on, Ordering::SeqCst),
            CLEAR_SITE_DATA_ON_EXIT_ID => self.site_data.store(on, Ordering::SeqCst),
            _ => return Err("not an exit setting".into()),
        }
        self.mark_pending();
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<bool> {
        match id {
            CLEAR_CACHE_ON_EXIT_ID => Some(self.cache.load(Ordering::SeqCst)),
            CLEAR_SITE_DATA_ON_EXIT_ID => Some(self.site_data.load(Ordering::SeqCst)),
            _ => None,
        }
    }

    fn write(&self, state: &str, kinds: ExitKinds, cookies_left: Option<u32>, detail: Option<String>) {
        let r = ExitRecord {
            state: state.into(),
            kinds,
            at: now(),
            cookies_left,
            detail,
        };
        if let Ok(json) = serde_json::to_vec_pretty(&r) {
            let tmp = self.path.with_extension("tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }
}

/// Called when the user closes the window. Returns true when closing must wait: the window is
/// hidden, the engine clears, and the window is destroyed when it has finished (or after
/// [`EXIT_TIMEOUT`]; the next start then clears first).
pub fn begin_exit_clear(app: &AppHandle) -> bool {
    let state = app.state::<AppState>();
    let kinds = state.exit_clear.kinds();
    if !kinds.any() || state.exit_clear.closing.swap(true, Ordering::SeqCst) {
        return false;
    }
    if host().is_none() {
        return false;
    }
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
    let finished = Arc::new(AtomicBool::new(false));
    let (a, fin) = (app.clone(), finished.clone());
    let started = exit_clear_run(kinds, move |result, left, detail| {
        finish_exit(&a, &fin, kinds, result, left, detail)
    });
    if !started {
        finish_exit(
            app,
            &finished,
            kinds,
            "failed",
            None,
            Some("the engine could not start clearing (no normal tab)".into()),
        );
        return true;
    }
    let (a, fin) = (app.clone(), finished);
    std::thread::spawn(move || {
        std::thread::sleep(EXIT_TIMEOUT);
        let a2 = a.clone();
        let _ = a.run_on_main_thread(move || finish_exit(&a2, &fin, kinds, "timed_out", None, None));
    });
    true
}

/// The engine part of clearing on exit, shared with the self-check (M7): clear what `kinds`
/// asks for, then, for site data, read back that no cookie is left. `done(result, cookies left,
/// detail)` runs on the UI thread; `result` is "done" or "failed". Returns false (and never
/// calls `done`) if the engine could not start clearing.
pub fn exit_clear_run(
    kinds: ExitKinds,
    done: impl FnOnce(&'static str, Option<u32>, Option<String>) + 'static,
) -> bool {
    let Some(h) = host() else {
        return false;
    };
    h.clear_data(kinds.clear_kinds(), move |r| match r {
        Ok(()) if kinds.site_data => match host() {
            Some(h) => h.cookie_sites(move |r| match r {
                Ok(sites) => {
                    let left: u32 = sites.iter().map(|s| s.cookies).sum();
                    done(if left == 0 { "done" } else { "failed" }, Some(left), None);
                }
                Err(e) => done("failed", None, Some(e)),
            }),
            None => done("failed", None, Some("engine gone".into())),
        },
        Ok(()) => done("done", None, None),
        Err(e) => done("failed", None, Some(e)),
    })
}

fn finish_exit(
    app: &AppHandle,
    finished: &AtomicBool,
    kinds: ExitKinds,
    result: &str,
    cookies_left: Option<u32>,
    detail: Option<String>,
) {
    if finished.swap(true, Ordering::SeqCst) {
        return;
    }
    let state = app.state::<AppState>();
    state.exit_clear.write(result, kinds, cookies_left, detail);
    let _ = state.audit.record(AuditEvent::DataCleared {
        what: format!("on exit: {}", kinds.describe()),
        ok: result == "done",
    });
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.destroy();
    }
}

/// D-013: delete crash reports older than [`CRASH_REPORT_DAYS`]. Returns how many were deleted.
pub fn prune_crash_reports(dirs: &[PathBuf], max_age: Duration) -> usize {
    let mut n = 0;
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(d) else { continue };
        for e in rd.flatten() {
            let old = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > max_age);
            if old && e.path().is_file() && std::fs::remove_file(e.path()).is_ok() {
                n += 1;
            }
        }
    }
    n
}

/// Where WebView2 puts crash reports for the content and UI environments.
pub fn crash_report_dirs(layout: &untrace_core::paths::Layout) -> Vec<PathBuf> {
    [&layout.content_webview, &layout.ui_webview]
        .iter()
        .map(|d| d.join("EBWebView").join("Crashpad").join("reports"))
        .collect()
}

// ------------------------------------------------------------ inventory

fn size_of(p: &Path) -> u64 {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::read_dir(p)
            .map(|rd| rd.flatten().map(|e| size_of(&e.path())).sum())
            .unwrap_or(0),
        Ok(m) => m.len(),
        Err(_) => 0,
    }
}

fn count_files(p: &Path) -> usize {
    std::fs::read_dir(p)
        .map(|rd| rd.flatten().filter(|e| e.path().is_file()).count())
        .unwrap_or(0)
}

/// Profile folders the engine fills with cache (relative to the profile folder) and, shared by
/// all profiles, at the top of its data folder.
const CACHE_DIRS: &[&str] = &[
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
];
const SHARED_CACHE_DIRS: &[&str] = &[
    "GrShaderCache",
    "ShaderCache",
    "GraphiteDawnCache",
    "GPUPersistentCache",
];
/// Cookies (in "Network") and site storage.
const SITE_DATA_DIRS: &[&str] = &[
    "Network",
    "Local Storage",
    "Session Storage",
    "IndexedDB",
    "Service Worker",
    "File System",
    "WebStorage",
    "databases",
    "Shared Dictionary",
    "SharedStorage",
    "blob_storage",
];
const HISTORY_FILES: &[&str] = &[
    "History",
    "History-journal",
    "Visited Links",
    "Top Sites",
    "Top Sites-journal",
    "Favicons",
    "Favicons-journal",
    "Network Action Predictor",
    "Network Action Predictor-journal",
];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataItem {
    pub id: &'static str,
    pub title: &'static str,
    /// What it is, in one or two sentences, with counts where UNTRACE knows them.
    pub what: String,
    pub location: Option<String>,
    pub bytes: Option<u64>,
    pub retention: String,
    /// Label of the button that deletes it now, if UNTRACE offers one.
    pub action: Option<&'static str>,
}

/// Facts the inventory needs from the engine (read on the UI thread).
#[derive(Debug, Clone, Default)]
pub struct EngineFacts {
    /// (sites, cookies) with cookies, or why they could not be read.
    pub cookies: Option<Result<(usize, u32), String>>,
    pub saved_permissions: usize,
    pub temporary_tabs: usize,
    pub downloads: usize,
}

pub fn inventory(state: &AppState, facts: &EngineFacts) -> Vec<DataItem> {
    let l = &state.layout;
    let engine = l.content_webview.join("EBWebView");
    let profile = engine.join("WV2Profile_standard");
    let sum = |base: &Path, names: &[&str]| names.iter().map(|n| size_of(&base.join(n))).sum::<u64>();
    let exit = state.exit_clear.kinds();
    let (exceptions, settings_file) = {
        let store = state.store.lock().unwrap();
        (store.settings().filter_exceptions.len(), store.path().to_path_buf())
    };
    let crash_dirs = crash_report_dirs(l);
    let crash_count: usize = crash_dirs.iter().map(|d| count_files(d)).sum();
    let cookies = match &facts.cookies {
        Some(Ok((sites, n))) => format!("{n} cookies from {sites} sites"),
        Some(Err(e)) => format!("Cookie count unavailable: {e}"),
        None => "Cookie count unavailable.".into(),
    };
    let cache_bytes = sum(&profile, CACHE_DIRS) + sum(&engine, SHARED_CACHE_DIRS);
    let site_bytes = sum(&profile, SITE_DATA_DIRS);
    let history_bytes = sum(&profile, HISTORY_FILES);
    let engine_total = size_of(&l.content_webview);
    let other_engine = engine_total.saturating_sub(cache_bytes + site_bytes + history_bytes);
    vec![
        DataItem {
            id: "site_data",
            title: "Cookies and site data",
            what: format!(
                "Sign-ins, preferences and storage that websites keep in normal tabs: {cookies}. Includes local \
                 storage, IndexedDB and service workers. Temporary tabs keep theirs only in memory."
            ),
            location: Some(profile.display().to_string()),
            bytes: Some(site_bytes),
            retention: if exit.site_data {
                "Deleted when UNTRACE closes.".into()
            } else {
                "Kept until you delete it: here, per site in the list below, or in the site panel. Settings \
                 can also delete it every time UNTRACE closes."
                    .into()
            },
            action: Some("Delete all"),
        },
        DataItem {
            id: "cache",
            title: "Cache",
            what: "Copies of pages, scripts and images, so sites load faster on the next visit. A cache also \
                   shows which sites were visited."
                .into(),
            location: Some(profile.join("Cache").display().to_string()),
            bytes: Some(cache_bytes),
            retention: if exit.cache {
                "Deleted when UNTRACE closes.".into()
            } else {
                "Kept and trimmed by the engine.".into()
            },
            action: Some("Delete now"),
        },
        DataItem {
            id: "history",
            title: "Engine browsing history",
            what: "UNTRACE has no history list, but the engine records visited pages for its own features. \
                   UNTRACE deletes that record every time it starts. The engine also keeps a per-site \
                   \"engagement\" score (which sites, how much they were used) in its settings file that none \
                   of its delete functions remove; UNTRACE removes those entries itself at every start, before \
                   the engine runs."
                .into(),
            location: Some(profile.join("History").display().to_string()),
            bytes: Some(history_bytes),
            retention: "History and engagement records are deleted at every start; delete the history now as \
                        well if you like."
                .into(),
            action: Some("Delete now"),
        },
        DataItem {
            id: "permissions",
            title: "Saved permission decisions",
            what: format!(
                "{} \"Remember for this site\" answer(s), such as camera or location access. Shown per site in \
                 the site panel.",
                facts.saved_permissions
            ),
            location: Some(profile.join("Preferences").display().to_string()),
            bytes: None,
            retention: "Kept until you reset them.".into(),
            action: (facts.saved_permissions > 0).then_some("Reset all"),
        },
        DataItem {
            id: "settings",
            title: "Settings",
            what: if exceptions > 0 {
                format!(
                    "Your choices in Settings, including {exceptions} site(s) where you turned blocking off. \
                     That list shows sites you chose, so UNTRACE lets you remove it."
                )
            } else {
                "Your choices in Settings. No site names are stored.".into()
            },
            location: Some(settings_file.display().to_string()),
            bytes: Some(size_of(&settings_file)),
            retention: "Kept until you change them.".into(),
            action: (exceptions > 0).then_some("Forget blocking exceptions"),
        },
        DataItem {
            id: "audit",
            title: "Activity log",
            what: "Settings changes, checks and errors, so you can see what UNTRACE did. It never contains \
                   web addresses or site names."
                .into(),
            location: Some(state.audit.path().display().to_string()),
            bytes: Some(state.audit.total_bytes()),
            retention: "At most 1 MB; the oldest entries are dropped.".into(),
            action: Some("Clear"),
        },
        DataItem {
            id: "crash_reports",
            title: "Crash reports",
            what: format!(
                "{crash_count} report(s) from engine crashes. They can contain parts of pages that were open. \
                 UNTRACE never uploads them."
            ),
            location: crash_dirs.first().map(|d| d.display().to_string()),
            bytes: Some(crash_dirs.iter().map(|d| size_of(d)).sum()),
            retention: format!("Deleted after {CRASH_REPORT_DAYS} days."),
            action: (crash_count > 0).then_some("Delete now"),
        },
        DataItem {
            id: "block_lists",
            title: "Block lists",
            what: "The ad, tracker, malware and phishing lists and UNTRACE's prepared copy of them. Public data; \
                   nothing about you."
                .into(),
            location: Some(l.root.join("filters").display().to_string()),
            bytes: Some(size_of(&l.root.join("filters"))),
            retention: "Replaced when a list updates; the previous copy is kept as a fallback.".into(),
            action: None,
        },
        DataItem {
            id: "engine_other",
            title: "Engine files",
            what: "Components and settings of the Microsoft WebView2 engine itself (certificate revocation \
                   lists, spelling, video decoders and similar)."
                .into(),
            location: Some(engine.display().to_string()),
            bytes: Some(other_engine),
            retention: "Managed by the engine.".into(),
            action: None,
        },
        network_item(state),
        DataItem {
            id: "memory",
            title: "Kept only in memory",
            what: format!(
                "Open tabs and their back/forward lists, what UNTRACE blocked on each page, the downloads list \
                 ({} item(s); the files stay where you saved them), \"Continue anyway\" choices, and \
                 {} temporary tab(s). All of it is gone when UNTRACE closes.",
                facts.downloads, facts.temporary_tabs
            ),
            location: None,
            bytes: None,
            retention: "Until UNTRACE closes (temporary tabs: until the last one closes).".into(),
            action: None,
        },
    ]
}

/// The network layer's records: memory only, never written to disk.
fn network_item(state: &AppState) -> DataItem {
    let (what, action) = match state.network().proxy() {
        Some(p) => (
            format!(
                "Names looked up this session ({} cached answer(s)) and the hosts the engine contacted ({}), shown in \
                 Diagnostics so you can see where connections went. Never written to disk.",
                p.resolver().cache_len(),
                p.hosts().len()
            ),
            Some("Forget now"),
        ),
        None => ("The network layer is off, so it keeps nothing.".to_string(), None),
    };
    DataItem {
        id: "network",
        title: "Network layer records (memory only)",
        what,
        location: None,
        bytes: None,
        retention: "Until UNTRACE closes. Cached DNS answers expire within 5 minutes.".into(),
        action,
    }
}

/// Run `start` on the UI thread with the content host and wait (on this worker thread) for
/// the value it sends back.
pub fn with_host<T: Send + 'static>(
    app: &AppHandle,
    start: impl FnOnce(ContentHost, mpsc::Sender<T>) + Send + 'static,
) -> Result<T, String> {
    let (tx, rx) = mpsc::channel();
    app.run_on_main_thread(move || {
        if let Some(h) = host() {
            start(h, tx);
        }
    })
    .map_err(|e| e.to_string())?;
    rx.recv_timeout(Duration::from_secs(20))
        .map_err(|_| "The browser engine did not answer.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("untrace-privacy-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("exit-clear.json")
    }

    #[test]
    fn a_session_that_never_finished_clearing_is_owed_at_the_next_start() {
        let path = temp_file("owed");
        let s = ExitClear::open(path.clone());
        s.set_initial(true, true);
        s.mark_pending(); // the session starts …and crashes
        let next = ExitClear::open(path);
        let owed = next.take_owed();
        assert_eq!(
            owed,
            ExitKinds {
                cache: true,
                site_data: true
            }
        );
        assert_eq!(next.startup(), Some(owed));
    }

    #[test]
    fn a_finished_or_failed_exit_is_recorded_and_only_failures_are_owed() {
        let path = temp_file("done");
        let s = ExitClear::open(path.clone());
        s.set_initial(true, false);
        s.write("done", s.kinds(), None, None);
        assert!(!ExitClear::open(path.clone()).take_owed().any());
        s.write("timed_out", s.kinds(), None, None);
        assert_eq!(
            ExitClear::open(path).take_owed(),
            ExitKinds {
                cache: true,
                site_data: false
            }
        );
    }

    #[test]
    fn turning_both_switches_off_removes_the_record() {
        let path = temp_file("off");
        let s = ExitClear::open(path.clone());
        s.set_initial(true, false);
        s.mark_pending();
        assert!(path.exists());
        s.set(CLEAR_CACHE_ON_EXIT_ID, false).unwrap();
        assert!(!path.exists());
        assert!(!ExitClear::open(path).take_owed().any());
        assert!(s.set("privacy.unknown", true).is_err());
    }

    #[test]
    fn old_crash_reports_are_pruned_and_new_ones_kept() {
        let dir = temp_file("crash").parent().unwrap().join("reports");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.dmp"), b"x").unwrap();
        assert_eq!(
            prune_crash_reports(std::slice::from_ref(&dir), Duration::from_secs(3600)),
            0
        );
        assert_eq!(prune_crash_reports(std::slice::from_ref(&dir), Duration::ZERO), 1);
        assert!(!dir.join("a.dmp").exists());
    }
}
