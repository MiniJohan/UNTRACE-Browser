//! Decisions taken on URLs and names that web pages control: navigation policy (HTTPS-only,
//! file links), app-link handling, download risk, tracking-parameter removal, local-address
//! classification and the audit log's scrubbing.
#![no_main]
use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use untrace_core::{audit, policy};
use untrace_filter::{params, registrable_domain};
use untrace_net::addr;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    for enabled in [true, false] {
        let https = policy::HttpsOnly { enabled, session_exceptions: BTreeSet::new() };
        let _ = policy::navigation(s, &https);
    }
    let _ = policy::http_fallback(s);
    let _ = policy::scheme_of(s);
    let _ = policy::external_scheme(s, true);
    let _ = policy::external_scheme(s, false);
    let _ = policy::download_risk(s);
    if let Some(c) = params::clean(s) {
        let _ = c;
    }
    let _ = registrable_domain(s);
    let _ = addr::literal(s);
    let _ = addr::is_local_name(s);
    let _ = addr::host_space(s);
    let _ = addr::page_space(s);
    let scrubbed = audit::scrub(s);
    assert!(!scrubbed.to_ascii_lowercase().contains("://"), "scrub left an address: {scrubbed:?}");
});
