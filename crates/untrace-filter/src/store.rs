//! Stored list copies, the last good copy, per-list status and the engine cache.
//!
//! Layout under `<data root>/filters/`:
//! - `<list>.txt` — current downloaded copy (validated before it was written)
//! - `<list>.prev.txt` — the copy before it, used if the current one is damaged
//! - `state.json` — per-list status (what Settings and Diagnostics show)
//! - `engine-<key>.bin` — cached ads/trackers engine; the key covers every input
//!
//! Stored copies carry a checksum, so loading them at startup does not re-parse every rule.

use std::{
    borrow::Cow,
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use untrace_core::store::write_atomic;

use crate::{
    catalog::{ListId, info},
    lists::{Checked, header},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// The snapshot shipped with UNTRACE.
    #[default]
    Bundled,
    /// Downloaded from the list's publisher.
    Downloaded,
    /// The downloaded copy was damaged; the previous download is in use.
    Previous,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCopy {
    pub version: Option<String>,
    pub rules: usize,
    pub expires_hours: u32,
    /// Unix seconds when it was downloaded.
    pub downloaded_at: u64,
    pub checksum: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListState {
    pub current: Option<StoredCopy>,
    pub previous: Option<StoredCopy>,
    /// Unix seconds of the last update attempt, successful or not.
    pub checked_at: Option<u64>,
    /// Why the last attempt failed (cleared by a successful one).
    pub last_error: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct StateFile {
    version: u32,
    lists: BTreeMap<ListId, ListState>,
}

/// List text ready to build from, and where it came from.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub id: ListId,
    pub text: Cow<'static, str>,
    pub origin: Origin,
    pub version: Option<String>,
    pub rules: usize,
    pub expires_hours: u32,
}

pub struct ListStore {
    dir: PathBuf,
    state: StateFile,
}

/// FNV-1a: detects damaged files (not tampering; the data folder belongs to the user).
pub fn checksum(text: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Rule-like lines, for display (downloads are counted exactly by validation).
fn rough_rules(text: &str) -> usize {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with(['!', '#', '[']))
        .count()
}

fn write_text_atomic(path: &Path, text: &str) -> io::Result<()> {
    let tmp = path.with_extension("txt.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

impl ListStore {
    const STATE_VERSION: u32 = 1;

    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let state = fs::read(dir.join("state.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<StateFile>(&b).ok())
            .filter(|s| s.version == Self::STATE_VERSION)
            .unwrap_or(StateFile {
                version: Self::STATE_VERSION,
                lists: BTreeMap::new(),
            });
        Ok(Self {
            dir: dir.to_path_buf(),
            state,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, id: ListId, previous: bool) -> PathBuf {
        self.dir
            .join(format!("{}{}.txt", id.stem(), if previous { ".prev" } else { "" }))
    }

    fn persist(&self) -> io::Result<()> {
        write_atomic(&self.dir.join("state.json"), &self.state)
    }

    pub fn state(&self, id: ListId) -> ListState {
        self.state.lists.get(&id).cloned().unwrap_or_default()
    }

    fn read_copy(&self, id: ListId, previous: bool, copy: Option<&StoredCopy>) -> Option<String> {
        let copy = copy?;
        let text = fs::read_to_string(self.path(id, previous)).ok()?;
        (checksum(&text) == copy.checksum).then_some(text)
    }

    /// The text to build from: the downloaded copy, else the previous download (if the current
    /// one is missing or damaged), else the bundled snapshot.
    pub fn load(&self, id: ListId) -> Loaded {
        let st = self.state(id);
        let i = info(id);
        for (previous, copy, origin) in [
            (false, st.current.as_ref(), Origin::Downloaded),
            (true, st.previous.as_ref(), Origin::Previous),
        ] {
            if let (Some(text), Some(c)) = (self.read_copy(id, previous, copy), copy) {
                return Loaded {
                    id,
                    text: Cow::Owned(text),
                    origin,
                    version: c.version.clone(),
                    rules: c.rules,
                    expires_hours: c.expires_hours,
                };
            }
        }
        let h = header(i.bundled);
        Loaded {
            id,
            text: Cow::Borrowed(i.bundled),
            origin: Origin::Bundled,
            version: h.version,
            rules: rough_rules(i.bundled),
            expires_hours: h.expires_hours.unwrap_or(i.default_expires_hours),
        }
    }

    /// Store a validated download: the current copy becomes the previous one.
    pub fn save_download(&mut self, id: ListId, checked: &Checked, now: u64) -> io::Result<()> {
        let mut st = self.state(id);
        if st.current.is_some() && self.path(id, false).exists() {
            let _ = fs::remove_file(self.path(id, true));
            fs::rename(self.path(id, false), self.path(id, true))?;
            st.previous = st.current.take();
        }
        write_text_atomic(&self.path(id, false), &checked.text)?;
        st.current = Some(StoredCopy {
            version: checked.header.version.clone(),
            rules: checked.rules,
            expires_hours: checked.header.expires_hours.unwrap_or(info(id).default_expires_hours),
            downloaded_at: now,
            checksum: checksum(&checked.text),
        });
        st.checked_at = Some(now);
        st.last_error = None;
        self.state.lists.insert(id, st);
        self.persist()
    }

    /// Record an update attempt that brought nothing new (`Ok`) or failed (`Err`).
    pub fn record_check(&mut self, id: ListId, now: u64, result: Result<(), String>) -> io::Result<()> {
        let mut st = self.state(id);
        st.checked_at = Some(now);
        st.last_error = result.err();
        self.state.lists.insert(id, st);
        self.persist()
    }

    /// Is an update attempt due? Lists say how often they change (`Expires`); after a failed
    /// attempt UNTRACE retries after an hour (or sooner if the list expires sooner).
    pub fn due(&self, id: ListId, now: u64) -> bool {
        let st = self.state(id);
        let Some(checked) = st.checked_at else { return true };
        let hours = u64::from(self.load_expires_hours(id));
        let wait = if st.last_error.is_some() { hours.min(1) } else { hours } * 3600;
        now >= checked.saturating_add(wait) || now < checked // clock moved back: check again
    }

    pub fn load_expires_hours(&self, id: ListId) -> u32 {
        let st = self.state(id);
        st.current.map(|c| c.expires_hours).unwrap_or_else(|| {
            header(info(id).bundled)
                .expires_hours
                .unwrap_or(info(id).default_expires_hours)
        })
    }

    /// Unix seconds when the next update attempt is due (for display).
    pub fn next_check(&self, id: ListId) -> Option<u64> {
        let st = self.state(id);
        let hours = u64::from(self.load_expires_hours(id));
        st.checked_at
            .map(|c| c + if st.last_error.is_some() { hours.min(1) } else { hours } * 3600)
    }

    fn cache_path(&self, key: u64) -> PathBuf {
        self.dir.join(format!("engine-{key:016x}.bin"))
    }

    pub fn read_cache(&self, key: u64) -> Option<Vec<u8>> {
        fs::read(self.cache_path(key)).ok()
    }

    /// Write the engine cache and remove older ones.
    pub fn write_cache(&self, key: u64, bytes: &[u8]) -> io::Result<()> {
        let path = self.cache_path(key);
        let tmp = path.with_extension("bin.tmp");
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, &path)?;
        if let Ok(entries) = fs::read_dir(&self.dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("engine-") && e.path() != path {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lists::validate;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("untrace-filter-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn easylist_variant(extra: &str) -> Checked {
        let i = info(ListId::EasyList);
        let text = format!("{}\n{extra}\n", i.bundled);
        validate(i, text.into_bytes(), None).unwrap()
    }

    #[test]
    fn first_run_uses_the_bundled_snapshot_and_is_due() {
        let dir = temp_dir("first");
        let s = ListStore::open(&dir).unwrap();
        let l = s.load(ListId::EasyList);
        assert_eq!(l.origin, Origin::Bundled);
        assert!(l.rules > 20_000);
        assert_eq!(l.expires_hours, 96);
        assert!(s.due(ListId::EasyList, 1_000));
    }

    #[test]
    fn downloads_replace_the_current_copy_and_keep_the_previous() {
        let dir = temp_dir("save");
        let mut s = ListStore::open(&dir).unwrap();
        let v1 = easylist_variant("||one.example^");
        s.save_download(ListId::EasyList, &v1, 1_000).unwrap();
        let v2 = easylist_variant("||two.example^");
        s.save_download(ListId::EasyList, &v2, 2_000).unwrap();
        let l = s.load(ListId::EasyList);
        assert_eq!(l.origin, Origin::Downloaded);
        assert!(l.text.contains("||two.example^"));
        // State survives a restart.
        let s2 = ListStore::open(&dir).unwrap();
        assert_eq!(s2.state(ListId::EasyList).current.unwrap().downloaded_at, 2_000);
        assert_eq!(s2.state(ListId::EasyList).previous.unwrap().downloaded_at, 1_000);
        // Not due right after a check; due once the list's interval (96 h) has passed.
        assert!(!s2.due(ListId::EasyList, 2_000 + 3_600));
        assert!(s2.due(ListId::EasyList, 2_000 + 96 * 3_600));
    }

    #[test]
    fn a_damaged_copy_falls_back_to_the_previous_one_then_the_bundled_one() {
        let dir = temp_dir("damage");
        let mut s = ListStore::open(&dir).unwrap();
        s.save_download(ListId::EasyList, &easylist_variant("||one.example^"), 1_000)
            .unwrap();
        s.save_download(ListId::EasyList, &easylist_variant("||two.example^"), 2_000)
            .unwrap();
        fs::write(dir.join("easylist.txt"), "damaged").unwrap();
        let l = s.load(ListId::EasyList);
        assert_eq!(l.origin, Origin::Previous);
        assert!(l.text.contains("||one.example^"));
        fs::write(dir.join("easylist.prev.txt"), "damaged too").unwrap();
        assert_eq!(s.load(ListId::EasyList).origin, Origin::Bundled);
    }

    #[test]
    fn failed_checks_are_retried_within_an_hour() {
        let dir = temp_dir("retry");
        let mut s = ListStore::open(&dir).unwrap();
        s.record_check(ListId::Malware, 10_000, Err("offline".into())).unwrap();
        assert_eq!(s.state(ListId::Malware).last_error.as_deref(), Some("offline"));
        assert!(!s.due(ListId::Malware, 10_000 + 1_800));
        assert!(s.due(ListId::Malware, 10_000 + 3_600));
        s.record_check(ListId::Malware, 20_000, Ok(())).unwrap();
        assert!(s.state(ListId::Malware).last_error.is_none());
        assert!(!s.due(ListId::Malware, 20_000 + 3_600));
        assert!(s.due(ListId::Malware, 20_000 + 12 * 3_600));
    }

    #[test]
    fn engine_cache_keeps_only_the_latest() {
        let dir = temp_dir("cache");
        let s = ListStore::open(&dir).unwrap();
        s.write_cache(1, b"one").unwrap();
        s.write_cache(2, b"two").unwrap();
        assert_eq!(s.read_cache(2).as_deref(), Some(&b"two"[..]));
        assert!(s.read_cache(1).is_none());
    }
}
