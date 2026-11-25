//! Settings persistence: validated on load, written atomically, never silently trusted.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{registry::ProtectionDef, settings::Settings};

/// Larger files are treated as damaged or tampered with.
const MAX_FILE_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LoadOutcome {
    Created,
    Loaded,
    Repaired { repairs: Vec<String> },
    Reset { reason: String, backup: Option<String> },
}

pub struct SettingsStore {
    path: PathBuf,
    settings: Settings,
    defs: Vec<ProtectionDef>,
}

impl SettingsStore {
    pub fn open(dir: &Path, defs: &[ProtectionDef]) -> io::Result<(Self, LoadOutcome)> {
        fs::create_dir_all(dir)?;
        let path = dir.join("settings.json");
        let defs = defs.to_vec();
        let mut store = Self {
            path: path.clone(),
            settings: Settings::default(),
            defs,
        };

        let meta = match fs::metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                write_atomic(&path, &store.settings)?;
                return Ok((store, LoadOutcome::Created));
            }
            Err(e) => return Err(e),
            Ok(m) => m,
        };
        if meta.len() > MAX_FILE_BYTES {
            let o = store.reset("settings file is unexpectedly large")?;
            return Ok((store, o));
        }
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => {
                let o = store.reset("settings file is not valid text")?;
                return Ok((store, o));
            }
        };
        let mut parsed: Settings = match serde_json::from_str(&text) {
            Ok(s) => s,
            Err(e) => {
                let o = store.reset(&format!("settings file could not be read ({e})"))?;
                return Ok((store, o));
            }
        };
        match parsed.validate(&store.defs) {
            Err(reason) => {
                let o = store.reset(&reason)?;
                Ok((store, o))
            }
            Ok(repairs) if repairs.is_empty() => {
                store.settings = parsed;
                Ok((store, LoadOutcome::Loaded))
            }
            Ok(repairs) => {
                write_atomic(&path, &parsed)?;
                store.settings = parsed;
                Ok((store, LoadOutcome::Repaired { repairs }))
            }
        }
    }

    /// Keep the unusable file for inspection, start from defaults.
    fn reset(&mut self, reason: &str) -> io::Result<LoadOutcome> {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup = self.path.with_file_name(format!("settings.invalid-{secs}.json"));
        let backup = fs::rename(&self.path, &backup)
            .ok()
            .map(|_| backup.display().to_string());
        self.settings = Settings::default();
        write_atomic(&self.path, &self.settings)?;
        Ok(LoadOutcome::Reset {
            reason: reason.to_string(),
            backup,
        })
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Modify, validate and persist atomically. In-memory state changes only if the write succeeds.
    pub fn update(&mut self, f: impl FnOnce(&mut Settings)) -> io::Result<()> {
        let mut next = self.settings.clone();
        f(&mut next);
        let repairs = next
            .validate(&self.defs)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        if !repairs.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, repairs.join("; ")));
        }
        write_atomic(&self.path, &next)?;
        self.settings = next;
        Ok(())
    }
}

/// Write to a temporary file, flush it to disk, then replace the target in one rename.
pub fn write_atomic<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&json)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        address::SearchEngine,
        registry::{Kind, Scope, Value},
        settings::Theme,
    };
    use std::sync::atomic::{AtomicU32, Ordering};

    pub(crate) fn temp_dir(tag: &str) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "untrace-test-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    const DEF: ProtectionDef = ProtectionDef {
        id: "browser.devtools",
        group: "Developer",
        title: "Developer tools",
        explanation: "",
        limitations: "",
        scope: Scope::View,
        kind: Kind::Toggle { default: false },
    };

    #[test]
    fn creates_defaults_then_round_trips() {
        let dir = temp_dir("store");
        let (mut s, o) = SettingsStore::open(&dir, &[DEF]).unwrap();
        assert_eq!(o, LoadOutcome::Created);
        s.update(|x| {
            x.theme = Theme::Light;
            x.protections.insert("browser.devtools".into(), Value::Bool(true));
        })
        .unwrap();
        let (s2, o2) = SettingsStore::open(&dir, &[DEF]).unwrap();
        assert_eq!(o2, LoadOutcome::Loaded);
        assert_eq!(s2.settings(), s.settings());
        assert!(!dir.join("settings.json.tmp").exists());
    }

    #[test]
    fn garbage_is_reset_with_backup() {
        let dir = temp_dir("store");
        fs::write(dir.join("settings.json"), "{ not json").unwrap();
        let (s, o) = SettingsStore::open(&dir, &[DEF]).unwrap();
        match o {
            LoadOutcome::Reset { backup: Some(b), .. } => assert!(Path::new(&b).exists()),
            other => panic!("expected reset, got {other:?}"),
        }
        assert_eq!(s.settings(), &Settings::default());
    }

    #[test]
    fn unknown_fields_and_wrong_schema_reset() {
        for text in [
            r#"{"schema":1,"theme":"dark","search":{"engine":"mojeek"},"protections":{},"extra":1}"#,
            r#"{"schema":2,"theme":"dark","search":{"engine":"mojeek"},"protections":{}}"#,
            r#"{"schema":1,"theme":"neon","search":{"engine":"mojeek"},"protections":{}}"#,
        ] {
            let dir = temp_dir("store");
            fs::write(dir.join("settings.json"), text).unwrap();
            let (_, o) = SettingsStore::open(&dir, &[DEF]).unwrap();
            assert!(matches!(o, LoadOutcome::Reset { .. }), "{text}");
        }
    }

    #[test]
    fn oversized_file_is_reset() {
        let dir = temp_dir("store");
        fs::write(dir.join("settings.json"), " ".repeat((MAX_FILE_BYTES + 1) as usize)).unwrap();
        let (_, o) = SettingsStore::open(&dir, &[DEF]).unwrap();
        assert!(matches!(o, LoadOutcome::Reset { .. }));
    }

    #[test]
    fn repairs_unknown_ids_bad_values_and_bad_templates() {
        let dir = temp_dir("store");
        fs::write(
            dir.join("settings.json"),
            r#"{"schema":1,"theme":"dark","search":{"engine":"custom","custom_template":"http://evil/?q={q}"},
                "protections":{"browser.devtools":"maybe","removed.thing":true}}"#,
        )
        .unwrap();
        let (s, o) = SettingsStore::open(&dir, &[DEF]).unwrap();
        let LoadOutcome::Repaired { repairs } = o else {
            panic!("expected repairs")
        };
        assert_eq!(repairs.len(), 3, "{repairs:?}");
        assert_eq!(s.settings().theme, Theme::Dark, "valid parts are kept");
        assert_eq!(s.settings().search.engine, SearchEngine::DuckDuckGo);
        assert_eq!(
            s.settings().protections.get("browser.devtools"),
            Some(&Value::Bool(false))
        );
        assert!(!s.settings().protections.contains_key("removed.thing"));
        // The repaired file is written back and now loads cleanly.
        assert_eq!(SettingsStore::open(&dir, &[DEF]).unwrap().1, LoadOutcome::Loaded);
    }

    #[test]
    fn update_rejects_invalid_values_without_writing() {
        let dir = temp_dir("store");
        let (mut s, _) = SettingsStore::open(&dir, &[DEF]).unwrap();
        let before = fs::read_to_string(s.path()).unwrap();
        let r = s.update(|x| {
            x.protections
                .insert("browser.devtools".into(), Value::Choice("x".into()));
        });
        assert!(r.is_err());
        assert_eq!(fs::read_to_string(s.path()).unwrap(), before);
        assert!(s.settings().protections.is_empty());
    }
}
