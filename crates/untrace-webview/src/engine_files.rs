//! Start-up clean-up of the engine's own state files (D-039, D-028). Runs only while the engine
//! is stopped, before UNTRACE starts it.
//!
//! - `<profile>\Preferences`: the engine keeps a per-origin "site engagement" (and "media
//!   engagement") record of every site visited, which none of its delete functions remove
//!   (M4 probe). UNTRACE empties both lists.
//! - `Local State`: the engine remembers every temporary (InPrivate) profile by name, and
//!   reopens the last used one at the next start, which recreates its folder. UNTRACE removes
//!   the temporary profiles' entries so their folders can be removed for good.
//!
//! Every edit is a JSON parse, a removal of exactly those entries, an atomic write and a
//! re-read to verify. A file that cannot be parsed is left untouched and reported.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use crate::host::TEMP_PROFILE_PREFIX;

const ENGAGEMENT_LISTS: [&str; 2] = ["site_engagement", "media_engagement"];

/// What the start-up clean-up did.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScrubReport {
    /// Site/media engagement records removed from profile preferences.
    pub engagement_removed: usize,
    /// Temporary-profile entries removed from the engine's profile list.
    pub temp_profile_entries_removed: usize,
    /// Folders left by temporary sessions, removed.
    pub temp_folders_removed: usize,
    /// Files re-read after editing and found clean.
    pub verified: bool,
    /// Files that could not be read, parsed or written (left untouched).
    pub problems: Vec<String>,
}

fn is_temp_profile(name: &str) -> bool {
    name.to_ascii_lowercase()
        .strip_prefix("wv2profile_")
        .is_some_and(|rest| rest.starts_with(TEMP_PROFILE_PREFIX))
}

/// Empty the engagement lists in one profile's preferences. Returns how many records went.
pub fn scrub_preferences(prefs: &mut Value) -> usize {
    let Some(exceptions) = prefs
        .pointer_mut("/profile/content_settings/exceptions")
        .and_then(Value::as_object_mut)
    else {
        return 0;
    };
    let mut removed = 0;
    for list in ENGAGEMENT_LISTS {
        if let Some(Value::Object(entries)) = exceptions.get_mut(list) {
            removed += entries.len();
            entries.clear();
        }
    }
    removed
}

/// True if no engagement record is left.
pub fn preferences_clean(prefs: &Value) -> bool {
    ENGAGEMENT_LISTS.iter().all(|list| {
        prefs
            .pointer(&format!("/profile/content_settings/exceptions/{list}"))
            .and_then(Value::as_object)
            .is_none_or(|m| m.is_empty())
    })
}

/// Remove temporary profiles from the engine's profile list. Returns how many entries went.
pub fn scrub_local_state(state: &mut Value) -> usize {
    let mut removed = 0;
    if let Some(profile) = state.get_mut("profile").and_then(Value::as_object_mut) {
        if let Some(Value::Object(cache)) = profile.get_mut("info_cache") {
            let before = cache.len();
            cache.retain(|k, _| !is_temp_profile(k));
            removed += before - cache.len();
        }
        for list in ["profiles_order", "last_active_profiles"] {
            if let Some(Value::Array(a)) = profile.get_mut(list) {
                let before = a.len();
                a.retain(|v| !v.as_str().is_some_and(is_temp_profile));
                removed += before - a.len();
            }
        }
        if profile
            .get("last_used")
            .and_then(Value::as_str)
            .is_some_and(is_temp_profile)
        {
            profile.remove("last_used"); // the engine then falls back to its default profile
            removed += 1;
        }
    }
    if let Some(Value::Object(groups)) = state.get_mut("variations_google_groups") {
        let before = groups.len();
        groups.retain(|k, _| !is_temp_profile(k));
        removed += before - groups.len();
    }
    removed
}

/// True if the engine's profile list names no temporary profile.
pub fn local_state_clean(state: &Value) -> bool {
    let p = &state["profile"];
    p["info_cache"]
        .as_object()
        .is_none_or(|m| !m.keys().any(|k| is_temp_profile(k)))
        && ["profiles_order", "last_active_profiles"].iter().all(|l| {
            p[*l]
                .as_array()
                .is_none_or(|a| !a.iter().any(|v| v.as_str().is_some_and(is_temp_profile)))
        })
        && !p["last_used"].as_str().is_some_and(is_temp_profile)
}

/// Parse a JSON file, apply `edit`, write it back atomically if anything changed, then re-read
/// and check it with `clean`. Returns (entries removed, verified).
fn edit_json(
    path: &Path,
    edit: impl Fn(&mut Value) -> usize,
    clean: impl Fn(&Value) -> bool,
) -> Result<(usize, bool), String> {
    let name = path.display().to_string();
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, true)),
        Err(e) => return Err(format!("{name}: {e}")),
    };
    let mut v: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("{name}: not readable ({e}); left as it is"))?;
    let removed = edit(&mut v);
    if removed > 0 {
        let out = serde_json::to_vec(&v).map_err(|e| format!("{name}: {e}"))?;
        let tmp = path.with_extension("untrace-tmp");
        std::fs::write(&tmp, out).map_err(|e| format!("{name}: {e}"))?;
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("{name}: {e}")
        })?;
    }
    let again: Value = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| format!("{name}: could not be read back"))?;
    Ok((removed, clean(&again)))
}

/// The engine's WebRTC policy that keeps WebRTC inside the network layer (D-052): only
/// connections through the proxy, so no UDP goes around it and no STUN/TURN name is looked up
/// outside it (M8 probe: `spikes/m8-fingerprint/RESULTS.md`).
pub const WEBRTC_PROXY_ONLY: &str = "disable_non_proxied_udp";

/// A profile's folder under the content data folder.
pub fn profile_dir(data_dir: &Path, profile: &str) -> PathBuf {
    data_dir.join("EBWebView").join(format!("WV2Profile_{profile}"))
}

fn webrtc_policy(prefs: &Value) -> Option<&str> {
    prefs.get("webrtc")?.get("ip_handling_policy")?.as_str()
}

/// Set UNTRACE's WebRTC policy in one profile's preferences (`proxy_only`), or remove it, before
/// the engine loads that profile. A new profile gets a preferences file holding only this. A
/// policy UNTRACE did not set is left alone. Returns the state read back from the file.
pub fn set_webrtc_policy(profile_dir: &Path, proxy_only: bool) -> Result<bool, String> {
    let path = profile_dir.join("Preferences");
    let name = path.display().to_string();
    let mut v: Value = match std::fs::read(&path) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{name}: not readable ({e}); left as it is"))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Value::Object(Default::default()),
        Err(e) => return Err(format!("{name}: {e}")),
    };
    let Some(obj) = v.as_object_mut() else {
        return Err(format!("{name}: unexpected content; left as it is"));
    };
    let ours = webrtc_policy(&Value::Object(obj.clone())) == Some(WEBRTC_PROXY_ONLY);
    if ours != proxy_only {
        if proxy_only {
            let w = obj.entry("webrtc").or_insert_with(|| Value::Object(Default::default()));
            if !w.is_object() {
                *w = Value::Object(Default::default());
            }
            w["ip_handling_policy"] = Value::String(WEBRTC_PROXY_ONLY.into());
        } else if let Some(w) = obj.get_mut("webrtc").and_then(Value::as_object_mut) {
            w.remove("ip_handling_policy");
        }
        std::fs::create_dir_all(profile_dir).map_err(|e| format!("{}: {e}", profile_dir.display()))?;
        let out = serde_json::to_vec(&v).map_err(|e| format!("{name}: {e}"))?;
        let tmp = path.with_extension("untrace-tmp");
        std::fs::write(&tmp, out).map_err(|e| format!("{name}: {e}"))?;
        std::fs::rename(&tmp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("{name}: {e}")
        })?;
    }
    let again: Value = match std::fs::read(&path) {
        Ok(b) => serde_json::from_slice(&b).map_err(|_| format!("{name}: could not be read back"))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !proxy_only => return Ok(false),
        Err(e) => return Err(format!("{name}: could not be read back ({e})")),
    };
    let set = webrtc_policy(&again) == Some(WEBRTC_PROXY_ONLY);
    if set != proxy_only {
        return Err(format!("{name}: the WebRTC policy did not read back"));
    }
    Ok(set)
}

fn profile_dirs(engine_dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(engine_dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().to_string();
                    (n == "Default" || n.to_ascii_lowercase().starts_with("wv2profile_")) && !is_temp_profile(&n)
                })
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default()
}

/// Clean the engine's state files under the content data folder. Call only while the engine is
/// not running (before UNTRACE starts it).
pub fn scrub_engine_files(data_dir: &Path) -> ScrubReport {
    let engine = data_dir.join("EBWebView");
    let mut r = ScrubReport {
        verified: true,
        ..Default::default()
    };
    // The profile list first: otherwise the engine reopens a temporary profile and recreates
    // the folder removed below.
    match edit_json(&engine.join("Local State"), scrub_local_state, local_state_clean) {
        Ok((n, ok)) => {
            r.temp_profile_entries_removed += n;
            r.verified &= ok;
        }
        Err(e) => {
            r.verified = false;
            r.problems.push(e);
        }
    }
    for dir in profile_dirs(&engine) {
        match edit_json(&dir.join("Preferences"), scrub_preferences, preferences_clean) {
            Ok((n, ok)) => {
                r.engagement_removed += n;
                r.verified &= ok;
            }
            Err(e) => {
                r.verified = false;
                r.problems.push(e);
            }
        }
    }
    r.temp_folders_removed = crate::host::remove_leftover_temp_profiles(data_dir);
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn engagement_lists_are_emptied_and_nothing_else_is_touched() {
        let mut p = json!({ "profile": { "content_settings": { "exceptions": {
            "site_engagement": { "https://a.example:443,*": { "setting": { "rawScore": 12.0 } },
                                 "http://b.example,*": { "setting": { "rawScore": 3.5 } } },
            "media_engagement": { "https://a.example:443,*": { "setting": { "visits": 1 } } },
            "geolocation": { "https://maps.example:443,*": { "setting": 1 } }
        } }, "name": "x" }, "big": 13439827230227397u64, "f": 1795355180.146484 });
        assert!(!preferences_clean(&p));
        assert_eq!(scrub_preferences(&mut p), 3);
        assert!(preferences_clean(&p));
        // Saved permissions and every other value survive exactly.
        assert_eq!(
            p["profile"]["content_settings"]["exceptions"]["geolocation"]["https://maps.example:443,*"]["setting"],
            1
        );
        assert_eq!(p["big"].as_u64(), Some(13439827230227397));
        assert_eq!(p["f"].as_f64(), Some(1795355180.146484));
        assert_eq!(scrub_preferences(&mut p), 0);
        assert_eq!(scrub_preferences(&mut json!({ "other": 1 })), 0);
    }

    #[test]
    fn temporary_profiles_leave_the_engine_profile_list() {
        let mut s = json!({
            "profile": {
                "info_cache": { "Default": {}, "WV2Profile_standard": {}, "WV2Profile_temp-8dd5": { "active_time": 1.0 } },
                "profiles_order": ["Default", "WV2Profile_standard", "WV2Profile_temp-8dd5"],
                "last_active_profiles": ["WV2Profile_temp-8dd5"],
                "last_used": "WV2Profile_temp-8dd5"
            },
            "variations_google_groups": { "WV2Profile_temp-8dd5": [], "WV2Profile_standard": [] }
        });
        assert!(!local_state_clean(&s));
        assert_eq!(scrub_local_state(&mut s), 5);
        assert!(local_state_clean(&s));
        assert_eq!(
            s["profile"]["profiles_order"],
            json!(["Default", "WV2Profile_standard"])
        );
        assert!(s["profile"]["info_cache"].get("WV2Profile_standard").is_some());
        assert!(s["profile"].get("last_used").is_none());
        assert!(s["variations_google_groups"].get("WV2Profile_standard").is_some());
    }

    #[test]
    fn files_are_edited_atomically_verified_and_unparseable_ones_left_alone() {
        let dir = std::env::temp_dir().join(format!("untrace-engine-files-{}", std::process::id()));
        let engine = dir.join("EBWebView");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(engine.join("WV2Profile_standard")).unwrap();
        std::fs::create_dir_all(engine.join("WV2Profile_temp-abc").join("Cache")).unwrap();
        std::fs::write(
            engine.join("Local State"),
            r#"{"profile":{"last_used":"WV2Profile_temp-abc","profiles_order":["WV2Profile_standard","WV2Profile_temp-abc"]}}"#,
        )
        .unwrap();
        std::fs::write(
            engine.join("WV2Profile_standard").join("Preferences"),
            r#"{"profile":{"content_settings":{"exceptions":{"site_engagement":{"https://a.example:443,*":{}}}}}}"#,
        )
        .unwrap();
        let r = scrub_engine_files(&dir);
        assert_eq!(
            (
                r.engagement_removed,
                r.temp_profile_entries_removed,
                r.temp_folders_removed
            ),
            (1, 2, 1)
        );
        assert!(r.verified && r.problems.is_empty(), "{r:?}");
        let prefs = std::fs::read_to_string(engine.join("WV2Profile_standard").join("Preferences")).unwrap();
        assert!(!prefs.contains("a.example"));
        assert!(!engine.join("WV2Profile_temp-abc").exists());
        // A damaged file is reported, not rewritten.
        std::fs::write(engine.join("WV2Profile_standard").join("Preferences"), b"{not json").unwrap();
        let r = scrub_engine_files(&dir);
        assert!(!r.verified && r.problems.len() == 1, "{r:?}");
        assert_eq!(
            std::fs::read(engine.join("WV2Profile_standard").join("Preferences")).unwrap(),
            b"{not json"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_webrtc_policy_is_set_and_removed_and_nothing_else_is_touched() {
        let dir = std::env::temp_dir().join(format!("untrace-webrtc-pref-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let read =
            |p: &Path| -> Value { serde_json::from_slice(&std::fs::read(p.join("Preferences")).unwrap()).unwrap() };

        // A new profile (no folder yet) gets a file holding only the policy.
        let fresh = profile_dir(&dir, "temp-abc");
        assert_eq!(set_webrtc_policy(&fresh, true), Ok(true));
        assert_eq!(
            read(&fresh),
            json!({ "webrtc": { "ip_handling_policy": WEBRTC_PROXY_ONLY } })
        );
        // Off for a profile that never had it: nothing is written.
        let none = profile_dir(&dir, "none");
        assert_eq!(set_webrtc_policy(&none, false), Ok(false));
        assert!(!none.exists());

        // An existing profile keeps every other value, including other WebRTC settings.
        let std_dir = profile_dir(&dir, "standard");
        std::fs::create_dir_all(&std_dir).unwrap();
        std::fs::write(
            std_dir.join("Preferences"),
            r#"{"big":13439827230227397,"webrtc":{"udp_port_range":"1-2"},"profile":{"name":"x"}}"#,
        )
        .unwrap();
        assert_eq!(set_webrtc_policy(&std_dir, true), Ok(true));
        let v = read(&std_dir);
        assert_eq!(v["webrtc"]["ip_handling_policy"], WEBRTC_PROXY_ONLY);
        assert_eq!(v["webrtc"]["udp_port_range"], "1-2");
        assert_eq!(v["big"].as_u64(), Some(13439827230227397));
        assert_eq!(set_webrtc_policy(&std_dir, true), Ok(true)); // already set: unchanged
        assert_eq!(set_webrtc_policy(&std_dir, false), Ok(false));
        let v = read(&std_dir);
        assert!(v["webrtc"].get("ip_handling_policy").is_none());
        assert_eq!(v["webrtc"]["udp_port_range"], "1-2");

        // A policy UNTRACE did not set is left alone when the switch is off.
        std::fs::write(
            std_dir.join("Preferences"),
            r#"{"webrtc":{"ip_handling_policy":"default_public_interface_only"}}"#,
        )
        .unwrap();
        assert_eq!(set_webrtc_policy(&std_dir, false), Ok(false));
        assert_eq!(
            read(&std_dir)["webrtc"]["ip_handling_policy"],
            "default_public_interface_only"
        );

        // A damaged file is reported and not rewritten.
        std::fs::write(std_dir.join("Preferences"), b"{not json").unwrap();
        assert!(set_webrtc_policy(&std_dir, true).is_err());
        assert_eq!(std::fs::read(std_dir.join("Preferences")).unwrap(), b"{not json");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
