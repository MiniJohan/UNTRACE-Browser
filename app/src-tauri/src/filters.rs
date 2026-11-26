//! Block lists (M3, D-032): which lists are on, building the filters the content host matches
//! against, list status for Settings/Diagnostics, and the combined applier that routes list
//! switches here and everything else to the content host.

use std::{
    collections::BTreeSet,
    io,
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tauri::{AppHandle, Manager};
use untrace_core::{
    registry::{Applier, Observed, Value},
    time::rfc3339,
};
use untrace_filter::{
    Format, Kind, ListId, catalog,
    engine::{ContentEngine, Filters, Source, Threats, cache_key},
    info, lists,
    store::{ListStore, Loaded, Origin},
};
use untrace_webview::ContentHost;

use crate::{AppState, fetch};

/// Settings switch for automatic list updates (D-016: on, disclosed, can be turned off).
pub const AUTO_UPDATE_ID: &str = "filter.auto_update";
/// How often the worker looks for lists that are due (each list says how often it changes).
const UPDATE_POLL: Duration = Duration::from_secs(15 * 60);
/// First look after start-up, once the first page has had time to load.
const UPDATE_FIRST: Duration = Duration::from_secs(30);

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What the last build actually loaded, per list.
#[derive(Debug, Clone)]
struct LoadedInfo {
    id: ListId,
    origin: Origin,
    version: Option<String>,
    rules: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListStatus {
    pub id: ListId,
    pub protection: &'static str,
    pub title: &'static str,
    pub kind: Kind,
    pub enabled: bool,
    /// Where the copy in use came from; `None` when the list is off.
    pub origin: Option<Origin>,
    pub version: Option<String>,
    pub rules: Option<usize>,
    pub expires_hours: u32,
    pub last_check: Option<String>,
    pub next_check: Option<String>,
    pub last_error: Option<String>,
    pub homepage: &'static str,
    pub licence: &'static str,
    pub url: &'static str,
}

pub struct FilterService {
    store: Mutex<ListStore>,
    enabled: Mutex<BTreeSet<ListId>>,
    loaded: Mutex<Vec<LoadedInfo>>,
    /// Milliseconds the last build took (Diagnostics), and whether the cache was used.
    last_build: Mutex<Option<(u128, bool)>>,
    auto_update: AtomicBool,
    updating: AtomicBool,
    /// Update runs started (automatic or "Check for new versions"); the self-check reads it.
    attempts: std::sync::atomic::AtomicU64,
}

impl FilterService {
    pub fn open(dir: &Path) -> io::Result<Self> {
        Ok(Self {
            store: Mutex::new(ListStore::open(dir)?),
            enabled: Mutex::new(BTreeSet::new()),
            loaded: Mutex::new(vec![]),
            last_build: Mutex::new(None),
            attempts: std::sync::atomic::AtomicU64::new(0),
            auto_update: AtomicBool::new(true),
            updating: AtomicBool::new(false),
        })
    }

    pub fn set_auto_update(&self, on: bool) {
        self.auto_update.store(on, Ordering::SeqCst);
    }

    pub fn auto_update(&self) -> bool {
        self.auto_update.load(Ordering::SeqCst)
    }

    pub fn attempts(&self) -> u64 {
        self.attempts.load(Ordering::SeqCst)
    }

    /// Download, validate and store every enabled list that is due (all of them with `force`).
    /// Blocking network I/O: worker threads only. Returns whether any list changed.
    pub fn update(&self, force: bool) -> Result<bool, String> {
        if self.updating.swap(true, Ordering::SeqCst) {
            return Err("an update is already running".into());
        }
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let enabled: Vec<ListId> = self.enabled.lock().unwrap().iter().copied().collect();
        let mut changed = false;
        for id in enabled {
            let now = unix_now();
            if !force && !self.store.lock().unwrap().due(id, now) {
                continue;
            }
            let l = info(id);
            // The store is not locked during the download (it can take seconds).
            let body = fetch::get(l.url, lists::MAX_BYTES).and_then(|r| match r.status {
                200 => Ok(r.body),
                s => Err(format!("the server answered with status {s}")),
            });
            let mut store = self.store.lock().unwrap();
            let outcome = body.and_then(|body| {
                let previous = store.state(id).current.map(|c| c.rules);
                let checked = lists::validate(l, body, previous).map_err(|r| format!("download refused: {r}"))?;
                if checked.header.version.is_some() && checked.header.version == store.load(id).version {
                    return Ok(false); // same version as the copy in use
                }
                store
                    .save_download(id, &checked, now)
                    .map_err(|e| format!("could not save the download: {e}"))?;
                Ok(true)
            });
            match outcome {
                Ok(true) => changed = true, // save_download recorded the check
                Ok(false) => {
                    let _ = store.record_check(id, now, Ok(()));
                }
                Err(e) => {
                    let _ = store.record_check(id, now, Err(e));
                }
            }
        }
        if changed {
            self.warm_cache();
        }
        self.updating.store(false, Ordering::SeqCst);
        Ok(changed)
    }

    /// Build and cache the ads/trackers engine for the current lists, so the UI thread's next
    /// build only loads (and verifies) the cache.
    fn warm_cache(&self) {
        let enabled: Vec<ListId> = self.enabled.lock().unwrap().iter().copied().collect();
        let store = self.store.lock().unwrap();
        let loaded: Vec<Loaded> = enabled.iter().map(|id| store.load(*id)).collect();
        let sources: Vec<Source> = loaded
            .iter()
            .map(|l| Source {
                id: l.id,
                text: &l.text,
            })
            .collect();
        let key = cache_key(&sources);
        if store.read_cache(key).is_none()
            && let Some(c) = ContentEngine::build(&sources)
        {
            let _ = store.write_cache(key, &c.serialize());
        }
    }

    /// The configured switches at startup (before the content host exists).
    pub fn set_initial(&self, enabled: impl IntoIterator<Item = ListId>) {
        *self.enabled.lock().unwrap() = enabled.into_iter().collect();
    }

    /// Turn one list on or off. Returns whether anything changed (and a rebuild is needed).
    pub fn set_enabled(&self, id: ListId, on: bool) -> bool {
        let mut e = self.enabled.lock().unwrap();
        if on { e.insert(id) } else { e.remove(&id) }
    }

    /// Build the filters for the enabled lists. The ads/trackers engine comes from the cache
    /// when its inputs are unchanged (a few milliseconds); otherwise it is built (~0.1 s) and
    /// cached. A cached engine is only used after it proves every list with its canary.
    pub fn build(&self) -> Filters {
        let started = std::time::Instant::now();
        let enabled: Vec<ListId> = self.enabled.lock().unwrap().iter().copied().collect();
        let store = self.store.lock().unwrap();
        let loaded: Vec<Loaded> = enabled.iter().map(|id| store.load(*id)).collect();
        let sources: Vec<Source> = loaded
            .iter()
            .map(|l| Source {
                id: l.id,
                text: &l.text,
            })
            .collect();
        let content_ids: Vec<ListId> = sources
            .iter()
            .filter(|s| info(s.id).format == Format::Adblock)
            .map(|s| s.id)
            .collect();
        let mut cached = false;
        let content = if content_ids.is_empty() {
            None
        } else {
            let key = cache_key(&sources);
            match store
                .read_cache(key)
                .and_then(|b| ContentEngine::deserialize(content_ids.clone(), &b).ok())
            {
                Some(c) => {
                    cached = true;
                    Some(c)
                }
                None => {
                    let c = ContentEngine::build(&sources);
                    if let Some(c) = &c {
                        let _ = store.write_cache(key, &c.serialize());
                    }
                    c
                }
            }
        };
        let threats = Threats::build(&sources);
        // M6: element-hiding rules from the same lists (about 50 ms for EasyList).
        let cosmetic = untrace_filter::cosmetic::CosmeticRules::build(&sources);
        // Pop-up rules, which the matching library drops (untrace_filter::popup).
        let popups = untrace_filter::popup::PopupRules::build(&sources);
        // D-057: scriptlet rules, run with uBlock Origin's bundled scriptlets.
        let scriptlets = untrace_filter::scriptlets::Scriptlets::build(&sources);
        drop(store);
        *self.loaded.lock().unwrap() = loaded
            .iter()
            .map(|l| LoadedInfo {
                id: l.id,
                origin: l.origin,
                version: l.version.clone(),
                rules: l.rules,
            })
            .collect();
        *self.last_build.lock().unwrap() = Some((started.elapsed().as_millis(), cached));
        Filters::new(content, threats)
            .with_cosmetic(cosmetic)
            .with_popups(popups)
            .with_scriptlets(scriptlets)
    }

    pub fn last_build(&self) -> Option<(u128, bool)> {
        *self.last_build.lock().unwrap()
    }

    pub fn status(&self) -> Vec<ListStatus> {
        let enabled = self.enabled.lock().unwrap().clone();
        let loaded = self.loaded.lock().unwrap().clone();
        let store = self.store.lock().unwrap();
        catalog()
            .iter()
            .map(|l| {
                let st = store.state(l.id);
                let used = loaded.iter().find(|x| x.id == l.id);
                ListStatus {
                    id: l.id,
                    protection: l.protection,
                    title: l.title,
                    kind: l.kind,
                    enabled: enabled.contains(&l.id),
                    origin: used.map(|u| u.origin),
                    version: used.and_then(|u| u.version.clone()),
                    rules: used.map(|u| u.rules),
                    expires_hours: store.load_expires_hours(l.id),
                    last_check: st.checked_at.map(rfc3339),
                    next_check: store.next_check(l.id).map(rfc3339),
                    last_error: st.last_error,
                    homepage: l.homepage,
                    licence: l.licence,
                    url: l.url,
                }
            })
            .collect()
    }
}

/// Swap freshly updated lists into the content host (UI thread).
pub fn reload_into_host(app: &AppHandle) {
    let a = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(h) = crate::host() {
            h.set_filters(a.state::<AppState>().filters.build());
        }
    });
}

/// Background updates: shortly after start-up, then every 15 minutes, download the lists that
/// are due — only while "Update block lists automatically" is on. Never started in self-check mode.
pub fn start_updater(app: AppHandle) {
    thread::spawn(move || {
        thread::sleep(UPDATE_FIRST);
        loop {
            updater_tick(&app);
            thread::sleep(UPDATE_POLL);
        }
    });
}

/// One round of the background updater: nothing at all unless "Update block lists
/// automatically" is on. Returns whether an update was attempted (the self-check tests the
/// switch with it, offline).
pub fn updater_tick(app: &AppHandle) -> bool {
    let state = app.state::<AppState>();
    if !state.filters.auto_update() {
        return false;
    }
    if matches!(state.filters.update(false), Ok(true)) {
        reload_into_host(app);
    }
    true
}

/// Routes list switches to the filter service, exit-clearing switches to the application, and
/// every other protection to the content host.
pub struct Applied<'a> {
    pub host: Option<ContentHost>,
    pub filters: &'a FilterService,
    pub exit: &'a crate::privacy::ExitClear,
    pub network: &'a crate::network::NetworkService,
}

impl Applier for Applied<'_> {
    fn apply(&mut self, id: &str, value: &Value) -> Result<(), String> {
        if self.exit.get(id).is_some() {
            let Value::Bool(on) = value else {
                return Err("expected on or off".into());
            };
            return self.exit.set(id, *on);
        }
        if id == AUTO_UPDATE_ID {
            let Value::Bool(on) = value else {
                return Err("expected on or off".into());
            };
            self.filters.set_auto_update(*on);
            return Ok(());
        }
        if id == crate::appupdate::AUTO_CHECK_ID {
            let Value::Bool(on) = value else {
                return Err("expected on or off".into());
            };
            crate::appupdate::set_enabled(*on);
            return Ok(());
        }
        if let Some(r) = self.network.apply(id, value) {
            return r;
        }
        let Some(host) = self.host.as_mut() else {
            return Err("the browser engine is not running".into());
        };
        let lists: Vec<ListId> = catalog::lists_for(id).map(|l| l.id).collect();
        if lists.is_empty() {
            return host.apply(id, value);
        }
        let Value::Bool(on) = value else {
            return Err("expected on or off".into());
        };
        // `|` not `||`: every list of the switch is set.
        let changed = lists.iter().fold(false, |c, l| self.filters.set_enabled(*l, *on) | c);
        if changed {
            host.set_filters(self.filters.build());
        }
        Ok(())
    }

    fn observe(&self, id: &str) -> Observed {
        if let Some(on) = self.exit.get(id) {
            // UNTRACE's own close handler reads this; what each exit actually cleared is recorded
            // and shown in Diagnostics.
            return Observed::Verified(Value::Bool(on));
        }
        if id == AUTO_UPDATE_ID {
            // UNTRACE's own update worker reads this flag before every check.
            return Observed::Verified(Value::Bool(self.filters.auto_update()));
        }
        if id == crate::appupdate::AUTO_CHECK_ID {
            return crate::appupdate::observe();
        }
        if let Some(o) = self
            .network
            .observe(id, self.host.as_ref().map(ContentHost::network_check))
        {
            return o;
        }
        let Some(host) = &self.host else {
            return Observed::Unverifiable("The browser engine is not running.".into());
        };
        let lists: Vec<ListId> = catalog::lists_for(id).map(|l| l.id).collect();
        if lists.is_empty() {
            return host.observe(id);
        }
        // A switch over several lists is verified only if every list reports the same state.
        let states: Vec<Observed> = lists.iter().map(|l| host.filter_state(*l)).collect();
        if let Some(u) = states.iter().find(|o| matches!(o, Observed::Unverifiable(_))) {
            return u.clone();
        }
        if states.windows(2).all(|w| w[0] == w[1]) {
            states
                .into_iter()
                .next()
                .unwrap_or(Observed::Unverifiable("no list".into()))
        } else {
            Observed::Unverifiable("its lists report different states".into())
        }
    }
}
