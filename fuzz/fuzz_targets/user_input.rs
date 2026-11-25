//! What the user types or pastes, and what reaches Rust through IPC commands: the address
//! bar, custom search templates, site names, custom encrypted-DNS servers and protection
//! values.
#![no_main]
use libfuzzer_sys::fuzz_target;
use untrace_core::{
    address::{self, SearchEngine},
    settings::{self, CustomDoh},
};
use untrace_net::resolver;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let (a, b) = s.split_once('\u{1}').unwrap_or((s, ""));
    for e in [SearchEngine::DuckDuckGo, SearchEngine::Startpage, SearchEngine::BraveSearch, SearchEngine::Mojeek, SearchEngine::Custom] {
        let _ = address::resolve(a, e, Some(b));
        let _ = address::resolve(a, e, None);
        let _ = address::search_url(a, e, Some(b));
    }
    if address::validate_template(a).is_ok() {
        // A valid template always yields a search URL.
        assert!(address::search_url("x", SearchEngine::Custom, Some(a)).is_ok(), "template {a:?}");
    }
    // The IPC commands' site-name check (app/src-tauri commands::site_name).
    let site = a.trim().to_ascii_lowercase();
    let canonical = untrace_filter::registrable_domain(&format!("https://{site}/"));
    if settings::is_site_name(&site) && canonical.as_deref() == Some(site.as_str()) {
        assert!(!site.contains(['/', ':', '@', ' ']), "site {site:?}");
    }
    let doh = CustomDoh { template: a.to_string(), address: b.to_string() };
    let shape_ok = doh.is_valid();
    let net_ok = resolver::custom_server(a, b).is_ok();
    // untrace-net checks again before use; it must never accept what settings refuse.
    assert!(!net_ok || shape_ok, "custom DoH {a:?} / {b:?}: net accepts, settings refuse");
});
