//! M7: the self-check, run from Diagnostics. A second UNTRACE starts with `--self-check`: its own
//! window, its own data folder (`<data root>\self-check`), no network, no single-instance lock.
//! The user's tabs, settings and data are not touched. Its report is kept and shown per
//! protection in Diagnostics and Settings.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    process::Command,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value as Json, json};
use tauri::{AppHandle, Emitter, Manager};
use untrace_core::audit::AuditEvent;

use crate::AppState;

/// A full run takes about two minutes; a run that has not finished by then is ended.
const LIMIT: Duration = Duration::from_secs(360);

#[derive(Default)]
pub struct SelfTest {
    running: AtomicBool,
    last: Mutex<Option<Json>>,
}

/// Where the test instance writes its report (inside its own data folder).
pub fn report_path() -> PathBuf {
    untrace_core::paths::data_root().join("self-check").join("report.json")
}

impl SelfTest {
    /// The report of the last run, if one exists (also from an earlier session).
    pub fn load(&self) {
        let report = std::fs::read(report_path())
            .ok()
            .and_then(|b| serde_json::from_slice::<Json>(&b).ok())
            .filter(|v| v["checks"].is_array());
        *self.last.lock().unwrap() = report;
    }

    pub fn running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn last(&self) -> Option<Json> {
        self.last.lock().unwrap().clone()
    }

    /// Protection id → `{ state, at, failed }` from the last report.
    pub fn by_protection(&self) -> BTreeMap<String, Json> {
        let Some(r) = self.last() else {
            return BTreeMap::new();
        };
        r["protections"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| {
                        Some((
                            p["id"].as_str()?.to_string(),
                            json!({ "state": p["state"], "at": r["at"], "failed": p["failed"] }),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Start a run. Returns at once; the UI gets a `selftest-done` event with the summary.
pub fn start(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    if state.selftest.running.swap(true, Ordering::SeqCst) {
        return Err("A self-check is already running.".into());
    }
    let out = report_path();
    let _ = std::fs::create_dir_all(out.parent().unwrap_or(&out));
    let _ = std::fs::remove_file(&out);
    let child = std::env::current_exe().map_err(|e| e.to_string()).and_then(|exe| {
        Command::new(exe)
            .arg("--self-check")
            .arg(&out)
            .spawn()
            .map_err(|e| e.to_string())
    });
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            state.selftest.running.store(false, Ordering::SeqCst);
            return Err(format!("The self-check could not start ({e})."));
        }
    };
    let a = app.clone();
    thread::spawn(move || {
        let started = Instant::now();
        let finished = loop {
            match child.try_wait() {
                Ok(Some(_)) => break true,
                Ok(None) if started.elapsed() < LIMIT => thread::sleep(Duration::from_millis(500)),
                _ => {
                    let _ = child.kill();
                    break false;
                }
            }
        };
        let state = a.state::<AppState>();
        state.selftest.load();
        let report = state.selftest.last();
        state.selftest.running.store(false, Ordering::SeqCst);
        let summary = match (&report, finished) {
            (Some(r), _) => {
                let failed: Vec<String> = r["checks"]
                    .as_array()
                    .map(|c| {
                        c.iter()
                            .filter(|i| i["ok"] == false)
                            .filter_map(|i| i["name"].as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let skipped: Vec<String> = r["checks"]
                    .as_array()
                    .map(|c| {
                        c.iter()
                            .filter(|i| i["skipped"] == true)
                            .filter_map(|i| i["name"].as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let _ = state.audit.record(AuditEvent::SelfCheck {
                    passed: failed.is_empty(),
                    failed: failed.clone(),
                });
                json!({ "ok": true, "passed": failed.is_empty(), "failed": failed, "skipped": skipped })
            }
            (None, true) => json!({ "ok": false, "error": "The self-check ended without writing a report." }),
            (None, false) => {
                json!({ "ok": false, "error": "The self-check did not finish within 6 minutes and was stopped." })
            }
        };
        let _ = a.emit_to("main", "selftest-done", summary);
    });
    Ok(())
}
