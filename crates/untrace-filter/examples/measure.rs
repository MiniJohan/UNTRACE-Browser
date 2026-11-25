//! Measure the filter engine with the bundled lists (development tool).
//!   cargo run --release -p untrace-filter --example measure

use std::time::Instant;

use untrace_filter::{
    ListId,
    engine::{ContentEngine, Filters, ResourceKind, Source, Threats},
    info,
    lists::validate,
};

fn main() {
    for id in ListId::ALL {
        let i = info(id);
        let t = Instant::now();
        let c = validate(i, i.bundled.as_bytes().to_vec(), None).expect("valid");
        println!(
            "{:<12} {:>7} rules  version {:<22} expires {:>3} h  validate {:>4} ms",
            i.title,
            c.rules,
            c.header.version.unwrap_or_default(),
            c.header.expires_hours.unwrap_or_default(),
            t.elapsed().as_millis()
        );
    }
    let sources: Vec<Source> = ListId::ALL
        .iter()
        .map(|id| Source {
            id: *id,
            text: info(*id).bundled,
        })
        .collect();

    let t = Instant::now();
    let content = ContentEngine::build(&sources).expect("engine");
    let build_ms = t.elapsed().as_secs_f64() * 1e3;
    let bytes = content.serialize();
    let t = Instant::now();
    let restored = ContentEngine::deserialize(content.lists().to_vec(), &bytes).expect("restore");
    let restore_ms = t.elapsed().as_secs_f64() * 1e3;
    let t = Instant::now();
    let threats = Threats::build(&sources);
    let threats_ms = t.elapsed().as_secs_f64() * 1e3;
    println!(
        "content engine: build {build_ms:.0} ms, cache {:.1} MB, load+verify {restore_ms:.1} ms; threat sets: {threats_ms:.1} ms ({} malware, {} phishing hosts)",
        bytes.len() as f64 / 1e6,
        threats.len(ListId::Malware),
        threats.len(ListId::Phishing)
    );
    drop(content);

    let f = Filters::new(Some(restored), threats);
    let hosts = [
        "www.google-analytics.com",
        "cdn.jsdelivr.net",
        "news.example.org",
        "static.doubleclick.net",
        "fonts.gstatic.com",
        "connect.facebook.net",
        "images.example-cdn.com",
        "api.example.org",
    ];
    let kinds = [
        ResourceKind::Script,
        ResourceKind::Image,
        ResourceKind::Xhr,
        ResourceKind::Stylesheet,
    ];
    let urls: Vec<(String, ResourceKind)> = (0..50_000)
        .map(|n| {
            (
                format!("https://{}/path/{n}/file{}.js?x={n}", hosts[n % hosts.len()], n % 7),
                kinds[n % kinds.len()],
            )
        })
        .collect();
    let mut times = Vec::with_capacity(urls.len());
    let mut blocked = 0;
    for (u, k) in &urls {
        let t = Instant::now();
        if f.check(u, "https://news.example.org/article", *k) != untrace_filter::Verdict::Allow {
            blocked += 1;
        }
        times.push(t.elapsed().as_secs_f64() * 1e6);
    }
    times.sort_by(f64::total_cmp);
    let pct = |p: f64| times[((times.len() as f64 - 1.0) * p) as usize];
    println!(
        "matching {} requests: p50 {:.1} µs, p99 {:.1} µs, max {:.0} µs ({blocked} blocked)",
        times.len(),
        pct(0.5),
        pct(0.99),
        pct(1.0)
    );
}
