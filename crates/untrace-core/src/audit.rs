//! Minimal local audit log: JSON lines, size-capped, rotated once, never contains URLs.
//!
//! Events are a closed set of structured records. As defence in depth, every string field is
//! scrubbed of anything that looks like a URL or host-plus-path before it is written.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::Serialize;

pub const MAX_BYTES: u64 = 512 * 1024;
const MAX_STRING: usize = 300;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    AppStarted {
        version: String,
    },
    EngineReady {
        runtime_version: String,
    },
    ConfigLoaded {
        outcome: String,
    },
    SettingChanged {
        id: String,
        from: String,
        to: String,
        verified: bool,
    },
    SettingReverted {
        id: String,
        attempted: String,
        reason: String,
    },
    SelfCheck {
        passed: bool,
        failed: Vec<String>,
    },
    LogCleared,
    /// Browsing data removed (by the user, or on exit/start). `what` names a category, never a
    /// site: the log must not reveal where the user has been.
    DataCleared {
        what: String,
        ok: bool,
    },
    Error {
        component: String,
        message: String,
    },
    /// The network layer (M5): started, its start-up check, or why it could not start. Never
    /// names a site.
    NetworkLayer {
        state: String,
    },
    /// The user saved a copy of this log (M7). The file's location is not recorded.
    LogExported {
        entries: usize,
    },
    /// The user saved a security report (M7). The file's location is not recorded.
    ReportSaved,
    /// M9: a check for, or the installation of, an UNTRACE update.
    AppUpdate {
        result: String,
    },
}

pub struct AuditLog {
    path: PathBuf,
    max_bytes: u64,
    lock: Mutex<()>,
}

/// Replace URL-like tokens and cap length.
pub fn scrub(s: &str) -> String {
    let out: Vec<String> = s
        .split(' ')
        .map(|w| {
            let lw = w.to_ascii_lowercase();
            let urlish = lw.contains("://")
                || lw.starts_with("www.")
                || (lw.contains('.') && lw.contains('/') && !lw.starts_with('/') && !lw.contains('\\'));
            if urlish {
                "[url removed]".to_string()
            } else {
                w.to_string()
            }
        })
        .collect();
    let mut s = out.join(" ");
    if s.chars().count() > MAX_STRING {
        s = s.chars().take(MAX_STRING).collect::<String>() + "…";
    }
    s
}

fn scrub_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => *s = scrub(s),
        serde_json::Value::Array(a) => a.iter_mut().for_each(scrub_value),
        serde_json::Value::Object(o) => o.values_mut().for_each(scrub_value),
        _ => {}
    }
}

impl AuditLog {
    pub fn open(dir: &Path) -> io::Result<Self> {
        Self::open_with_limit(dir, MAX_BYTES)
    }

    pub fn open_with_limit(dir: &Path, max_bytes: u64) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            path: dir.join("audit.log"),
            max_bytes,
            lock: Mutex::new(()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record(&self, event: AuditEvent) -> io::Result<()> {
        let mut v = serde_json::to_value(&event).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        scrub_value(&mut v);
        if let serde_json::Value::Object(o) = &mut v {
            o.insert("ts".into(), serde_json::Value::String(crate::time::now_rfc3339()));
        }
        let line = format!("{v}\n");
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let size = fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if size + line.len() as u64 > self.max_bytes {
            let _ = fs::rename(&self.path, self.path.with_extension("1.log"));
        }
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        f.write_all(line.as_bytes())
    }

    /// Last `n` lines (current file only).
    pub fn tail(&self, n: usize) -> Vec<String> {
        let text = fs::read_to_string(&self.path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(n)..]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Every entry, oldest first: the previous file (kept when the log reached its size limit),
    /// then the current one.
    pub fn all(&self) -> Vec<String> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        [self.path.with_extension("1.log"), self.path.clone()]
            .iter()
            .filter_map(|p| fs::read_to_string(p).ok())
            .flat_map(|t| t.lines().map(str::to_string).collect::<Vec<_>>())
            .filter(|l| !l.trim().is_empty())
            .collect()
    }

    pub fn clear(&self) -> io::Result<()> {
        {
            let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
            let _ = fs::remove_file(self.path.with_extension("1.log"));
            let _ = fs::remove_file(&self.path);
        }
        self.record(AuditEvent::LogCleared)
    }

    pub fn total_bytes(&self) -> u64 {
        [self.path.clone(), self.path.with_extension("1.log")]
            .iter()
            .filter_map(|p| fs::metadata(p).ok())
            .map(|m| m.len())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::temp_dir;

    #[test]
    fn scrubs_url_like_tokens() {
        assert_eq!(
            scrub("failed for https://bank.example/login?x=1 now"),
            "failed for [url removed] now"
        );
        assert_eq!(scrub("visit www.example.com"), "visit [url removed]");
        assert_eq!(scrub("host example.org/path"), "host [url removed]");
        assert_eq!(scrub("plain message, version 1.2"), "plain message, version 1.2");
        assert_eq!(scrub(&"x".repeat(400)).chars().count(), MAX_STRING + 1);
    }

    #[test]
    fn records_json_lines_with_timestamps_and_no_urls() {
        let dir = temp_dir("audit");
        let log = AuditLog::open(&dir).unwrap();
        log.record(AuditEvent::Error {
            component: "net".into(),
            message: "lookup https://secret.example/a failed".into(),
        })
        .unwrap();
        let tail = log.tail(1);
        let v: serde_json::Value = serde_json::from_str(&tail[0]).unwrap();
        assert_eq!(v["event"], "error");
        assert!(v["ts"].as_str().unwrap().ends_with('Z'));
        assert!(!tail[0].contains("secret.example"));
    }

    #[test]
    fn rotates_when_full_and_clears() {
        let dir = temp_dir("audit");
        let log = AuditLog::open_with_limit(&dir, 1024).unwrap();
        for i in 0..60 {
            log.record(AuditEvent::AppStarted {
                version: format!("{i}"),
            })
            .unwrap();
        }
        assert!(dir.join("audit.1.log").exists());
        assert!(log.total_bytes() <= 2 * 1024 + 200);
        // Reading everything spans both files, oldest first, and ends with the newest entry.
        let all = log.all();
        assert!(all.len() > log.tail(1000).len());
        assert!(all.last().unwrap().contains("\"59\""));
        let versions: Vec<u32> = all
            .iter()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v["version"].as_str().and_then(|s| s.parse().ok()))
            .collect();
        assert!(versions.windows(2).all(|w| w[0] < w[1]), "oldest first");
        log.clear().unwrap();
        assert!(!dir.join("audit.1.log").exists());
        assert_eq!(log.tail(10).len(), 1, "only the log_cleared event remains");
    }
}
