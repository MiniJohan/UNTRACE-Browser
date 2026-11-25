//! Request matching against the bundled lists with URLs a page chooses (every request is
//! checked, so a panic here would take down the content host).
#![no_main]
use libfuzzer_sys::fuzz_target;
use untrace_filter::{Filters, ListId, ResourceKind, engine::Source, info};

thread_local! {
    // Built once (the engine is not Sync; libFuzzer runs inputs on one thread).
    static FILTERS: Filters = {
        let sources: Vec<Source> = ListId::ALL.iter().map(|id| Source { id: *id, text: info(*id).bundled }).collect();
        Filters::build(&sources)
    };
}

const KINDS: [ResourceKind; 11] = [
    ResourceKind::Document,
    ResourceKind::Subdocument,
    ResourceKind::Script,
    ResourceKind::Stylesheet,
    ResourceKind::Image,
    ResourceKind::Font,
    ResourceKind::Media,
    ResourceKind::Xhr,
    ResourceKind::Ping,
    ResourceKind::WebSocket,
    ResourceKind::Other,
];

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let (url, src) = s.split_once('\u{1}').unwrap_or((s, "https://example.com/"));
    let kind = KINDS[url.len() % KINDS.len()];
    FILTERS.with(|f| {
        let _ = f.check(url, src, kind);
        let _ = f.threat(url);
        if let Some(c) = f.cosmetic() {
            let _ = c.for_host(url);
        }
    });
});
