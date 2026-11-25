//! The settings file (config.json) as read at start: tampered or corrupted files must be
//! rejected or repaired, never crash UNTRACE or let an invalid value through.
#![no_main]
use libfuzzer_sys::fuzz_target;
use untrace_core::{
    registry::{Kind, ProtectionDef, Scope, Value},
    settings::{self, Settings},
};

const DEFS: &[ProtectionDef] = &[
    ProtectionDef {
        id: "filter.block_ads",
        group: "Blocking",
        title: "t",
        explanation: "e",
        limitations: "l",
        scope: Scope::Profile,
        kind: Kind::Toggle { default: true },
    },
    ProtectionDef {
        id: "privacy.tracking_prevention",
        group: "Privacy",
        title: "t",
        explanation: "e",
        limitations: "l",
        scope: Scope::Environment,
        kind: Kind::Choice { options: &["basic", "balanced", "strict"], default: "balanced" },
    },
];

fuzz_target!(|data: &[u8]| {
    let Ok(mut s) = serde_json::from_slice::<Settings>(data) else { return };
    if s.validate(DEFS).is_ok() {
        // After validation every stored value is one its protection accepts, and every site
        // name is a valid one.
        for (id, v) in &s.protections {
            if let Some(d) = DEFS.iter().find(|d| d.id == id) {
                assert!(d.accepts(v), "{id} = {v:?} accepted");
            }
        }
        for site in s.filter_exceptions.iter().chain(&s.local_network_sites) {
            assert!(settings::is_site_name(site), "site {site:?} accepted");
        }
        if let Some(c) = &s.custom_doh {
            assert!(c.is_valid(), "custom DoH {c:?} accepted");
        }
    }
    let _ = Value::Bool(true);
});
