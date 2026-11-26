//! Downloaded block lists (untrusted until validated): validation, header parsing and the
//! host lists behind the malware/phishing warnings.
#![no_main]
use libfuzzer_sys::fuzz_target;
use untrace_filter::{ListId, info, lists};

fuzz_target!(|data: &[u8]| {
    let pick = data.first().copied().unwrap_or(0) as usize;
    let id = ListId::ALL[pick % ListId::ALL.len()];
    let body = data.get(1..).unwrap_or(&[]).to_vec();
    let _ = lists::validate(info(id), body.clone(), None);
    let _ = lists::validate(info(id), body.clone(), Some(50_000));
    if let Ok(text) = std::str::from_utf8(&body) {
        let _ = lists::header(text);
        let (hosts, _) = lists::hosts(text);
        for h in hosts.iter().take(64) {
            assert!(!h.is_empty() && !h.contains(char::is_whitespace), "host {h:?}");
        }
        let _ = lists::parse_expires(text);
        let _ = lists::normalise_host(text);
        // D-057: uBlock Origin's directives and the pop-up rule rewriting read downloaded text.
        let pre = untrace_filter::preprocess::preprocess(text);
        assert!(pre.len() <= text.len() + text.lines().count(), "preprocessing only removes lines");
        let split = untrace_filter::popup::split(&pre);
        for r in split.popup.iter().chain(&split.rest) {
            assert!(!r.contains('\n'), "a rewritten rule stays one line");
        }
        // D-058: the network builders' text (regular expressions the library cannot compile
        // dropped) only removes lines, and leaves none of those behind.
        let net = untrace_filter::preprocess::network_text(&untrace_filter::engine::Source { id, text });
        assert!(net.lines().count() <= text.lines().count(), "only removes lines");
        assert_eq!(untrace_filter::preprocess::unsupported_regex_rules(&net), 0);
    }
});
