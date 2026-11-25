//! Real-site compatibility runner (M1 gate, TESTING §7). Not shipped.
//!
//! Browses a list of sites in a content host configured exactly like UNTRACE's (dedicated
//! environment, hardening, M1 interim defaults) and records what happened on each page.
//!
//! Usage:
//!   cargo run --release -p untrace-webview --example compat -- <sites.txt> <out.json> <data-dir> [mode] [rounds]
//!
//! `mode`:
//! - `on` (default since M3): the bundled lists, all switched on, as in a fresh UNTRACE;
//! - `off`: no block lists, as in M1;
//! - `paired` (M3 overhead budget, TESTING §4): two engines with separate fresh profiles, one
//!   with filtering off and one with it on. Each visits every site once; which goes first
//!   alternates per site and per round, so DNS and connection warm-up favour neither. Repeated
//!   `rounds` times (default 1), each round in new profiles.
//! - `paired-hide` (M6): the same design, filtering on in both, no network layer; "off" with
//!   element hiding switched off, "on" with it on (as in a fresh UNTRACE).
//! - `paired-net` (M5): the same design, filtering on in both; "off" without and "on" with the
//!   network layer (loopback proxy, Automatic encrypted DNS, as in a fresh UNTRACE).
//! - `net`: one engine with filtering and the network layer on.

use std::{
    rc::Rc,
    sync::mpsc,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use untrace_filter::{
    ListId,
    engine::{Filters, Source},
};
use untrace_webview::{ContentHost, HostConfig, HostEvent, TabInfo};
use windows::{
    Win32::{
        Foundation::*,
        System::{
            Com::{COINIT_APARTMENTTHREADED, CoInitializeEx},
            LibraryLoader::GetModuleHandleW,
        },
        UI::{
            HiDpi::{DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext},
            WindowsAndMessaging::*,
        },
    },
    core::*,
};

const PROBE: &str = "({ href: location.href, readyState: document.readyState, \
textLength: ((document.body && document.body.innerText) || '').length, \
images: document.images.length, frames: window.frames.length, scripts: document.scripts.length, \
resources: performance.getEntriesByType('resource').length, \
loadEventMs: (() => { const n = performance.getEntriesByType('navigation')[0]; return n ? Math.round(n.loadEventEnd) : null; })() })";

/// With `UNTRACE_DETAIL=1`: which requests were answered 403 (blocked) and which finished last,
/// to find what holds a page's load event back.
const DETAIL: &str = "(() => { const n = performance.getEntriesByType('navigation')[0]; const r = performance.getEntriesByType('resource'); const m = e => ({ u: e.name.slice(0, 160), t: e.initiatorType, s: Math.round(e.startTime), e: Math.round(e.responseEnd), st: e.responseStatus }); return { dcl: n && Math.round(n.domContentLoadedEventEnd), load: n && Math.round(n.loadEventStart), blocked: r.filter(e => e.responseStatus === 403).map(m), latest: [...r].sort((a, b) => b.responseEnd - a.responseEnd).slice(0, 10).map(m) }; })()";

fn pump_for(d: Duration) {
    let deadline = Instant::now() + d;
    while Instant::now() < deadline {
        pump_once();
    }
}

fn pump_once() {
    // SAFETY: standard message pumping on this (UI) thread.
    unsafe {
        let mut msg = MSG::default();
        while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        MsgWaitForMultipleObjects(None, false, 10, QS_ALLINPUT);
    }
}

fn until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        pump_once();
    }
    cond()
}

extern "system" fn wndproc(h: HWND, m: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    // SAFETY: default handling for our own window.
    unsafe { DefWindowProcW(h, m, w, l) }
}

fn window() -> HWND {
    // SAFETY: plain Win32 window creation on the UI thread.
    unsafe {
        let hinst = HINSTANCE(GetModuleHandleW(None).expect("module").0);
        let class = w!("UntraceCompatRunner");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            lpszClassName: class,
            hInstance: hinst,
            ..Default::default()
        };
        RegisterClassW(&wc);
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            w!("UNTRACE compatibility run"),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            60,
            60,
            1280,
            860,
            None,
            None,
            Some(hinst),
            None,
        )
        .expect("window")
    }
}

fn tab(host: &ContentHost, id: u32) -> TabInfo {
    host.snapshot().tabs.into_iter().find(|t| t.id == id).expect("tab")
}

fn bundled_filters() -> Filters {
    let sources: Vec<Source> = ListId::ALL
        .iter()
        .map(|id| Source {
            id: *id,
            text: untrace_filter::info(*id).bundled,
        })
        .collect();
    Filters::build(&sources)
}

fn client_rect(hwnd: HWND) -> RECT {
    let mut r = RECT::default();
    // SAFETY: reading our own window's client rectangle.
    unsafe {
        let _ = GetClientRect(hwnd, &mut r);
    }
    r
}

/// The network layer's resolver: Automatic (UNTRACE's default), or Strict with a provider named
/// in `UNTRACE_COMPAT_DNS` (quad9, cloudflare, mullvad).
fn compat_dns_mode() -> untrace_net::Mode {
    match std::env::var("UNTRACE_COMPAT_DNS")
        .ok()
        .and_then(|p| untrace_net::resolver::provider(&p))
    {
        Some(p) => untrace_net::Mode::Strict {
            name: p.name.into(),
            servers: p.servers(),
        },
        None => untrace_net::Mode::Automatic,
    }
}

/// A content host with one ready tab, filling the window's client area.
fn open_host(hwnd: HWND, data: std::path::PathBuf, filtering: bool, network: bool, hide: bool) -> (ContentHost, u32) {
    let cfg = HostConfig {
        data_dir: data,
        profile: "standard".into(),
        devtools: false,
        https_only: true,
        background: [14, 14, 15],
        network: network.then(|| untrace_net::Proxy::start(compat_dns_mode()).expect("network layer")),
        // As UNTRACE ships (D-052).
        webrtc_proxy_only: true,
    };
    let host = ContentHost::new(hwnd, cfg, Rc::new(|_: HostEvent| {})).expect("content host");
    if filtering {
        host.set_filters(bundled_filters());
    }
    if hide && std::env::var("UNTRACE_COMPAT_NO_SITE_RULES").is_ok() {
        host.set_cosmetic_site_rules_for_measurement(false);
    }
    if !hide {
        use untrace_core::registry::{Applier, Value};
        let mut h = host.clone();
        h.apply(untrace_webview::HIDE_ELEMENTS_ID, &Value::Bool(false))
            .expect("hiding off");
    }
    host.set_bounds(client_rect(hwnd), true);
    let id = host.new_tab(None);
    assert!(
        until(Duration::from_secs(30), || tab(&host, id).ready),
        "engine did not start"
    );
    // The first tab's own blank page must finish first, or its completion is taken for the
    // site's (the paired run's first pair measured 8 ms before this wait).
    pump_for(Duration::from_millis(1500));
    until(Duration::from_secs(10), || !tab(&host, id).loading);
    (host, id)
}

/// Load one site in the tab and record what happened.
fn visit(host: &ContentHost, id: u32, url: &str) -> Value {
    until(Duration::from_secs(10), || !tab(host, id).loading);
    host.navigate_active(url);
    let t0 = Instant::now();
    let started = until(Duration::from_secs(5), || tab(host, id).loading);
    let finished = until(Duration::from_secs(30), || !tab(host, id).loading);
    let load_ms = t0.elapsed().as_millis();
    pump_for(Duration::from_secs(3)); // client-side redirects, late scripts
    let (tx, rx) = mpsc::channel();
    host.execute(id, PROBE, move |j| {
        let _ = tx.send(j);
    });
    let mut probe = Value::Null;
    until(Duration::from_secs(10), || match rx.try_recv() {
        Ok(j) => {
            probe = serde_json::from_str(&j).unwrap_or(Value::String(j));
            true
        }
        Err(_) => false,
    });
    let mut detail = Value::Null;
    if std::env::var_os("UNTRACE_DETAIL").is_some() {
        let (tx, rx) = mpsc::channel();
        host.execute(id, DETAIL, move |j| {
            let _ = tx.send(j);
        });
        until(Duration::from_secs(10), || match rx.try_recv() {
            Ok(j) => {
                detail = serde_json::from_str(&j).unwrap_or(Value::String(j));
                true
            }
            Err(_) => false,
        });
    }
    let t = tab(host, id);
    json!({
        "detail": detail,
        "input": url,
        "started": started,
        "finished": finished,
        "load_ms": load_ms,
        "final_url": t.url,
        "title": t.title,
        "http_status": t.http_status,
        "error": t.last_error,
        "crashed": t.crashed,
        "blocked": t.blocked,
        "interstitial": t.interstitial,
        "probe": probe,
    })
}

fn line(v: &Value) -> String {
    format!(
        "{:>6} ms  http={} err={} text={} blocked={}+{}",
        v["load_ms"],
        v["http_status"],
        if v["error"].is_null() { "none" } else { "yes" },
        v["probe"]["textLength"],
        v["blocked"]["requests"],
        v["blocked"]["threats"]
    )
}

/// The page loaded: navigation finished without an error, panel or crash.
fn loaded(v: &Value) -> bool {
    v["started"] == true
        && v["finished"] == true
        && v["error"].is_null()
        && v["interstitial"].is_null()
        && v["crashed"] == false
        && v["http_status"].as_i64().is_none_or(|s| s < 400)
}

/// Nearest-rank percentile (the same method as the M1/M3 comparisons).
fn pct(values: &[f64], p: f64) -> f64 {
    let mut s = values.to_vec();
    s.sort_by(f64::total_cmp);
    s[((s.len() - 1) as f64 * p).floor() as usize]
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// Compare filtering off and on over the pairs where both loads succeeded.
fn compare(ok: &[&Value], get: impl Fn(&Value) -> Option<f64>) -> Value {
    let both: Vec<(f64, f64)> = ok
        .iter()
        .filter_map(|p| Some((get(&p["off"])?, get(&p["on"])?)))
        .collect();
    if both.is_empty() {
        return Value::Null;
    }
    let off: Vec<f64> = both.iter().map(|b| b.0).collect();
    let on: Vec<f64> = both.iter().map(|b| b.1).collect();
    let ratio: Vec<f64> = both.iter().map(|b| b.1 / b.0.max(1.0)).collect();
    let (m_off, m_on, p_off, p_on) = (pct(&off, 0.5), pct(&on, 0.5), pct(&off, 0.95), pct(&on, 0.95));
    json!({
        "pairs": both.len(),
        "off": { "median": m_off, "p95": p_off },
        "on": { "median": m_on, "p95": p_on },
        "median_change_pct": round1((m_on / m_off - 1.0) * 100.0),
        "p95_change_pct": round1((p_on / p_off - 1.0) * 100.0),
        "paired_ratio_on_over_off": {
            "median": (pct(&ratio, 0.5) * 1000.0).round() / 1000.0,
            "p95": (pct(&ratio, 0.95) * 1000.0).round() / 1000.0,
        },
        "on_faster_in": both.iter().filter(|b| b.1 < b.0).count(),
    })
}

fn summary(pairs: &[Value]) -> Value {
    let ok: Vec<&Value> = pairs.iter().filter(|p| loaded(&p["off"]) && loaded(&p["on"])).collect();
    let failed: Vec<Value> = pairs
        .iter()
        .filter(|p| !(loaded(&p["off"]) && loaded(&p["on"])))
        .map(|p| {
            json!({
                "input": p["input"], "round": p["round"],
                "off": { "loaded": loaded(&p["off"]), "http": p["off"]["http_status"] },
                "on": { "loaded": loaded(&p["on"]), "http": p["on"]["http_status"] },
            })
        })
        .collect();
    let blocked: Vec<f64> = ok
        .iter()
        .filter_map(|p| p["on"]["blocked"]["requests"].as_f64())
        .collect();
    let resources = |k: &str| -> Vec<f64> { ok.iter().filter_map(|p| p[k]["probe"]["resources"].as_f64()).collect() };
    let (r_off, r_on) = (resources("off"), resources("on"));
    json!({
        "pairs_total": pairs.len(),
        "pairs_loaded_both": ok.len(),
        "failed": failed,
        "load_ms": compare(&ok, |v| v["load_ms"].as_f64()),
        "load_event_ms": compare(&ok, |v| v["probe"]["loadEventMs"].as_f64().filter(|x| *x > 0.0)),
        "blocked_requests_per_page": if blocked.is_empty() { Value::Null } else {
            json!({ "median": pct(&blocked, 0.5), "max": pct(&blocked, 1.0), "total": blocked.iter().sum::<f64>() })
        },
        "resources_per_page": if r_off.is_empty() || r_on.is_empty() { Value::Null } else {
            json!({ "off_median": pct(&r_off, 0.5), "on_median": pct(&r_on, 0.5) })
        },
    })
}

/// `compat visit <url> <data dir>` (M8): open one page in UNTRACE's content host with its
/// defaults (block lists, network layer, element hiding) and wait until the page sets its
/// title to "fp-done" (at most 90 s). The page reports its own results.
fn visit_one(url: &str, data: std::path::PathBuf) {
    let hwnd = window();
    let (host, id) = open_host(hwnd, data, true, true, true);
    host.navigate_active(url);
    let done = until(Duration::from_secs(90), || {
        let (tx, rx) = mpsc::channel();
        host.execute(id, "document.title", move |j| {
            let _ = tx.send(j);
        });
        let mut title = String::new();
        until(Duration::from_secs(5), || match rx.try_recv() {
            Ok(j) => {
                title = j;
                true
            }
            Err(_) => false,
        });
        pump_for(Duration::from_millis(300));
        title == "\"fp-done\""
    });
    eprintln!("visit {url}: {}", if done { "done" } else { "timed out" });
    pump_for(Duration::from_millis(500));
    host.shutdown();
    pump_for(Duration::from_millis(500));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("visit") {
        // SAFETY: COM/DPI initialisation for this UI thread.
        unsafe {
            CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok().expect("COM");
            let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        }
        visit_one(&args[2], std::path::PathBuf::from(&args[3]));
        return;
    }
    let (sites, out, data) = (&args[1], &args[2], std::path::PathBuf::from(&args[3]));
    let mode = args.get(4).map(String::as_str).unwrap_or("on");
    // SAFETY: COM/DPI initialisation for this UI thread.
    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok().expect("COM");
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
    let hwnd = window();
    let list: Vec<String> = std::fs::read_to_string(sites)
        .expect("sites file")
        .lines()
        .map(|l| l.trim().trim_start_matches('\u{feff}'))
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();

    if mode == "paired" || mode == "paired-net" || mode == "paired-hide" {
        let net = mode == "paired-net";
        let hide_pair = mode == "paired-hide";
        let rounds: usize = args.get(5).and_then(|r| r.parse().ok()).unwrap_or(1);
        eprintln!(
            "{mode}: {} off vs on, {rounds} round(s), fresh profiles per round",
            if net {
                "network layer (filtering on in both)"
            } else if hide_pair {
                "element hiding (filtering on in both, no network layer)"
            } else {
                "filtering (bundled lists)"
            }
        );
        let mut pairs = Vec::new();
        for round in 0..rounds {
            let (off, off_tab) = open_host(
                hwnd,
                data.join(format!("r{}-off", round + 1)),
                net || hide_pair,
                false,
                !hide_pair,
            );
            let (on, on_tab) = open_host(hwnd, data.join(format!("r{}-on", round + 1)), true, net, true);
            for (n, url) in list.iter().enumerate() {
                let on_first = (n + round) % 2 == 0;
                let run = |filtering: bool| {
                    let (h, t, other) = if filtering {
                        (&on, on_tab, &off)
                    } else {
                        (&off, off_tab, &on)
                    };
                    other.set_bounds(client_rect(hwnd), false);
                    h.set_bounds(client_rect(hwnd), true);
                    visit(h, t, url)
                };
                let first = run(on_first);
                let second = run(!on_first);
                let (v_on, v_off) = if on_first { (first, second) } else { (second, first) };
                eprintln!(
                    "[r{} {:>2}/{}] {:<42} off {} | on {}",
                    round + 1,
                    n + 1,
                    list.len(),
                    url,
                    line(&v_off),
                    line(&v_on)
                );
                pairs.push(json!({
                    "input": url,
                    "round": round + 1,
                    "first": if on_first { "on" } else { "off" },
                    "off": v_off,
                    "on": v_on,
                }));
            }
            off.shutdown();
            on.shutdown();
            pump_for(Duration::from_secs(2));
        }
        let s = summary(&pairs);
        eprintln!("{}", serde_json::to_string_pretty(&s).expect("json"));
        let doc = json!({ "mode": mode, "summary": s, "pairs": pairs });
        std::fs::write(out, serde_json::to_string_pretty(&doc).expect("json")).expect("write results");
        return;
    }

    let filtering = mode != "off";
    let net = mode == "net";
    eprintln!(
        "filtering: {}; network layer: {}",
        if filtering { "on (bundled lists)" } else { "off" },
        if net { "on" } else { "off" }
    );
    let (host, id) = open_host(hwnd, data, filtering, net, true);
    let mut results = Vec::new();
    for (n, url) in list.iter().enumerate() {
        let v = visit(&host, id, url);
        eprintln!("[{:>2}/{}] {:<45} {}", n + 1, list.len(), url, line(&v));
        results.push(v);
    }
    std::fs::write(out, serde_json::to_string_pretty(&results).expect("json")).expect("write results");
    host.shutdown();
    pump_for(Duration::from_secs(2));
}
