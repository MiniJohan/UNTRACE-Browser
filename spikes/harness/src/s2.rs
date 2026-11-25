//! S2 — Request interception: coverage per request type, and the cost of intercepting
//! every request and matching it with adblock-rust (EasyList + EasyPrivacy).

use std::{
    cell::RefCell,
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

use adblock::{lists::ParseOptions, request::Request, Engine, FilterSet};
use serde_json::{json, Value};
use webview2_com::{Microsoft::Web::WebView2::Win32::*, *};
use windows::core::*;

use crate::{
    fixture::{self, Fixture, Req, Resp},
    host, note, pump,
};

const R_PATHS: &[&str] = &[
    "img-main.png", "script-main.js", "style.css", "imported.css", "font.woff2", "bg.png",
    "prefetch", "favicon.ico", "fetch-main", "xhr-main", "beacon-main", "img-sameframe.png",
    "img-crossframe.png", "fetch-crossframe", "fetch-dworker", "import-dworker.js",
    "fetch-sharedworker", "websocket", "eventsource", "fetch-sw-install", "fetch-sw-message",
    "fetch-through-sw",
];
const DOC_PATHS: &[&str] = &[
    "/s2/main.html", "/s2/main.js", "/s2/frame-same.html", "/s2/frame-cross.html",
    "/s2/worker.js", "/s2/shared.js", "/s2/sw.js", "/s2/controlled.html",
];

const MAIN_JS: &str = r#"(async () => {
  try { await fetch('/s2/r/fetch-main'); } catch (e) {}
  try { const x = new XMLHttpRequest(); x.open('GET', '/s2/r/xhr-main'); x.send(); } catch (e) {}
  try { navigator.sendBeacon('/s2/r/beacon-main', 'x'); } catch (e) {}
  try { new Worker('/s2/worker.js'); } catch (e) {}
  try { const s = new SharedWorker('/s2/shared.js'); s.port.start(); } catch (e) {}
  try { new WebSocket('ws://localhost:{P}/s2/r/websocket'); } catch (e) {}
  try { new EventSource('/s2/r/eventsource'); } catch (e) {}
  try {
    const reg = await navigator.serviceWorker.register('/s2/sw.js', { scope: '/s2/' });
    await navigator.serviceWorker.ready;
    (reg.active || reg.waiting || reg.installing).postMessage('go');
  } catch (e) { window.__swerr = String(e); }
  setTimeout(() => { document.title = 's2-done'; }, 2500);
})();"#;

const SW_JS: &str = r#"
self.addEventListener('install', e => { e.waitUntil(fetch('/s2/r/fetch-sw-install').catch(() => {})); self.skipWaiting(); });
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('message', e => { fetch('/s2/r/fetch-sw-message').catch(() => {}); });
self.addEventListener('fetch', e => { if (e.request.url.includes('fetch-through-sw')) e.respondWith(fetch(e.request.url + '?via=sw')); });
"#;

fn router() -> fixture::Router {
    Arc::new(|r: &Req| {
        let p = r.port.to_string();
        let route = r.route().to_string();
        match route.as_str() {
            "/s2/main.html" => Resp::html(
                r#"<!doctype html><html><head><meta charset=utf-8><title>s2</title>
<link rel=stylesheet href="/s2/r/style.css"><link rel=prefetch href="/s2/r/prefetch"><link rel=icon href="/s2/r/favicon.ico">
<script src="/s2/r/script-main.js"></script></head><body><p class=f>text</p><img src="/s2/r/img-main.png">
<iframe src="http://localhost:{P}/s2/frame-same.html"></iframe><iframe src="http://127.0.0.1:{P}/s2/frame-cross.html"></iframe>
<script src="/s2/main.js"></script></body></html>"#
                    .replace("{P}", &p),
            ),
            "/s2/main.js" => Resp::js(MAIN_JS.replace("{P}", &p)),
            "/s2/worker.js" => Resp::js("fetch('/s2/r/fetch-dworker'); importScripts('/s2/r/import-dworker.js');"),
            "/s2/shared.js" => Resp::js("fetch('/s2/r/fetch-sharedworker'); onconnect = e => {};"),
            "/s2/sw.js" => Resp::js(SW_JS),
            "/s2/controlled.html" => Resp::html(
                "<!doctype html><title>c</title><script>fetch('/s2/r/fetch-through-sw').finally(() => { document.title = 's2-done2'; });</script>",
            ),
            "/s2/frame-same.html" => Resp::html("<!doctype html><img src=\"/s2/r/img-sameframe.png\">"),
            "/s2/frame-cross.html" => Resp::html(
                "<!doctype html><img src=\"/s2/r/img-crossframe.png\"><script>fetch('/s2/r/fetch-crossframe')</script>",
            ),
            "/s2/r/style.css" => Resp::css(
                "@import url(\"/s2/r/imported.css\"); @font-face { font-family: F; src: url(\"/s2/r/font.woff2\"); } .f { font-family: F; background: url(\"/s2/r/bg.png\"); }",
            ),
            "/s2/r/eventsource" => Resp::new(200, "text/event-stream", "data: x\n\n"),
            "/s2/r/websocket" => Resp::new(400, "text/plain", "no websocket here"),
            "/bench/page.html" => Resp::html(bench_page(r, &p)),
            _ if route.ends_with(".png") => Resp::png(),
            _ if route.ends_with(".js") => Resp::js(""),
            _ if route.ends_with(".css") => Resp::css(""),
            _ => Resp::text("ok"),
        }
    })
}

fn bench_page(r: &Req, port: &str) -> String {
    let run = r.path.split('?').nth(1).unwrap_or("");
    let mut s = String::from("<!doctype html><html><head><meta charset=utf-8><title>bench</title>");
    for i in 0..20 {
        s.push_str(&format!("<script src=\"/bench/js/lib{i}.js?{run}\"></script>"));
    }
    s.push_str("</head><body>");
    for i in 0..150 {
        s.push_str(&format!("<img width=4 height=4 src=\"/bench/img/photo{i}.png?{run}\">"));
    }
    for i in 0..50 {
        s.push_str(&format!("<img width=4 height=4 src=\"http://127.0.0.1:{port}/bench/cdn/asset{i}.png?{run}\">"));
    }
    s.push_str("<script>addEventListener('load', () => { const n = performance.getEntriesByType('navigation')[0]; window.__perf = { load: n.loadEventStart, resources: performance.getEntriesByType('resource').length }; });</script></body></html>");
    s
}

fn path_of(uri: &str) -> String {
    let after = uri.split("://").nth(1).unwrap_or(uri);
    let path = after.find('/').map(|i| &after[i..]).unwrap_or("/");
    path.split('?').next().unwrap_or("").to_string()
}

fn ctx_name(c: i32) -> &'static str {
    match c {
        1 => "document", 2 => "stylesheet", 3 => "image", 4 => "media", 5 => "font", 6 => "script",
        7 => "xhr", 8 => "fetch", 9 => "text_track", 10 => "event_source", 11 => "websocket",
        12 => "manifest", 13 => "signed_exchange", 14 => "ping", 15 => "csp_report", 16 => "other",
        _ => "?",
    }
}

fn kind_name(k: i32) -> &'static str {
    match k {
        1 => "document", 2 => "shared_worker", 4 => "service_worker", 0 => "none/unknown", _ => "other",
    }
}

fn adblock_type(c: i32) -> &'static str {
    match c {
        1 => "document", 2 => "stylesheet", 3 => "image", 4 => "media", 5 => "font", 6 => "script",
        7 | 8 => "xmlhttprequest", 11 => "websocket", 14 => "ping", _ => "other",
    }
}

type Seen = Rc<RefCell<Vec<(String, i32, i32)>>>;

fn record_requests(wv: &ICoreWebView2, seen: &Seen) {
    let s = seen.clone();
    let mut tok = 0i64;
    let h = WebResourceRequestedEventHandler::create(Box::new(move |_w, args| {
        if let Some(a) = args {
            let req = unsafe { a.Request()? };
            let mut p = PWSTR::null();
            unsafe { req.Uri(&mut p)? };
            let uri = host::take(p);
            let mut ctx = COREWEBVIEW2_WEB_RESOURCE_CONTEXT(0);
            unsafe { a.ResourceContext(&mut ctx)? };
            let mut kind = COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS(0);
            if let Ok(a2) = a.cast::<ICoreWebView2WebResourceRequestedEventArgs2>() {
                let _ = unsafe { a2.RequestedSourceKind(&mut kind) };
            }
            s.borrow_mut().push((uri, ctx.0, kind.0));
        }
        Ok(())
    }));
    unsafe { wv.add_WebResourceRequested(&h, &mut tok).expect("add_WebResourceRequested") };
}

fn coverage(fx: &Fixture, variant: &str) -> Value {
    note(&format!("S2 coverage: {variant}"));
    let udf = crate::fresh_udf(&format!("s2-{variant}"));
    let env = host::create_env(&udf, &host::EnvOpts { tracking_prevention: true, ..Default::default() });
    let hwnd = host::create_window(&format!("S2 coverage — {variant}"), 1000, 700);
    let ctrl = host::create_controller(&env, hwnd, "default", false);
    let wv = host::webview(&ctrl);
    unsafe {
        match variant {
            "legacy-filter" => wv
                .AddWebResourceRequestedFilter(w!("*"), COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL)
                .expect("filter"),
            _ => {
                let w22: ICoreWebView2_22 = wv.cast().expect("WebView2_22");
                w22.AddWebResourceRequestedFilterWithRequestSourceKinds(
                    w!("*"),
                    COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
                    COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_ALL,
                )
                .expect("filter with source kinds")
            }
        }
    }
    let seen: Seen = Default::default();
    record_requests(&wv, &seen);

    let mark = fx.mark();
    let base = format!("http://localhost:{}", fx.http_port);
    let nav1 = host::navigate(&wv, &format!("{base}/s2/main.html"), host::T);
    let done1 = host::wait_title(&wv, "s2-done", Duration::from_secs(12));
    let swerr = host::exec(&wv, "String(window.__swerr || '')");
    let nav2 = host::navigate(&wv, &format!("{base}/s2/controlled.html"), host::T);
    let done2 = host::wait_title(&wv, "s2-done2", Duration::from_secs(12));
    pump::sleep(Duration::from_millis(1500));

    let server = fx.since(mark);
    let events = seen.borrow().clone();
    let row = |path: &str, label: &str| {
        let srv: Vec<String> = server.iter().filter(|r| r.route() == path).map(|r| format!("{}:{}{}", r.host, r.port, r.path)).collect();
        let ev: Vec<Value> = events
            .iter()
            .filter(|(u, _, _)| path_of(u) == path)
            .map(|(u, c, k)| json!({ "uri": u, "context": ctx_name(*c), "source_kind": kind_name(*k) }))
            .collect();
        let verdict = match (srv.is_empty(), ev.is_empty()) {
            (true, true) => "not requested",
            (false, false) => "SEEN",
            (false, true) => "MISSED",
            (true, false) => "event only (served by cache/SW)",
        };
        json!({ "resource": label, "verdict": verdict, "server_count": srv.len(), "server": srv, "events": ev })
    };
    let mut rows: Vec<Value> = R_PATHS.iter().map(|n| row(&format!("/s2/r/{n}"), n)).collect();
    rows.extend(DOC_PATHS.iter().map(|p| row(p, p)));
    let missed: Vec<&str> = rows.iter().filter(|r| r["verdict"] == "MISSED").filter_map(|r| r["resource"].as_str()).collect();

    host::close(ctrl);
    host::destroy_window(hwnd);
    json!({
        "variant": variant,
        "navigation": [format!("{nav1:?}"), format!("{nav2:?}")],
        "page_scripts_completed": [done1, done2],
        "service_worker_error": swerr,
        "missed": missed,
        "rows": rows,
    })
}

fn build_engine() -> (Engine, Value) {
    let dir = crate::data_dir();
    let el = std::fs::read_to_string(dir.join("easylist.txt")).expect("easylist.txt");
    let ep = std::fs::read_to_string(dir.join("easyprivacy.txt")).expect("easyprivacy.txt");
    let lines = el.lines().count() + ep.lines().count();
    let t = Instant::now();
    let mut fs = FilterSet::new(false);
    fs.add_filter_list(el, ParseOptions::default());
    fs.add_filter_list(ep, ParseOptions::default());
    let engine = Engine::new_with_filter_set(fs);
    let build_ms = t.elapsed().as_secs_f64() * 1e3;
    let t = Instant::now();
    let bytes = engine.serialize();
    let ser_ms = t.elapsed().as_secs_f64() * 1e3;
    let mut e2 = Engine::default();
    let t = Instant::now();
    let de_ok = e2.deserialize(&bytes).is_ok();
    let de_ms = t.elapsed().as_secs_f64() * 1e3;

    let checks = [
        ("https://www.google-analytics.com/analytics.js", "https://news.example.org/", "script"),
        ("https://securepubads.g.doubleclick.net/tag/js/gpt.js", "https://news.example.org/", "script"),
        ("https://connect.facebook.net/en_US/fbevents.js", "https://shop.example.org/", "script"),
        ("https://news.example.org/static/app.js", "https://news.example.org/", "script"),
        ("https://cdn.jsdelivr.net/npm/react@18.3.1/umd/react.production.min.js", "https://example.org/", "script"),
        ("https://example.org/?utm_source=x&gclid=1&id=7", "https://example.org/", "document"),
    ];
    let known: Vec<Value> = checks
        .iter()
        .map(|(u, s, t)| {
            let r = Request::new(u, s, t, "GET").expect("request");
            let b = e2.check_network_request(&r);
            json!({ "url": u, "blocked": b.should_block(), "rewritten": b.rewritten_url })
        })
        .collect();

    // Micro-benchmark on synthetic third-party and first-party URLs.
    let n = 50_000;
    let reqs: Vec<Request> = (0..n)
        .map(|i| {
            let url = match i % 4 {
                0 => format!("https://cdn{}.example-static.com/assets/img/photo{i}.jpg?w=640", i % 97),
                1 => format!("https://news.example.org/js/chunk.{i:x}.js"),
                2 => format!("https://api.example-service.net/v2/items/{i}?fields=id,name"),
                _ => format!("https://tracker{}.example-metrics.io/collect?id={i}&ev=view", i % 13),
            };
            let ty = ["image", "script", "xmlhttprequest", "ping"][i % 4];
            Request::new(&url, "https://news.example.org/article/1", ty, "GET").expect("req")
        })
        .collect();
    let t = Instant::now();
    let mut blocked = 0;
    for r in &reqs {
        if e2.check_network_request(r).should_block() {
            blocked += 1;
        }
    }
    let per_ns = t.elapsed().as_nanos() as f64 / n as f64;
    let stats = json!({
        "list_lines": lines,
        "build_ms": build_ms,
        "serialized_bytes": bytes.len(),
        "serialize_ms": ser_ms,
        "deserialize_ms": de_ms,
        "deserialize_ok": de_ok,
        "known_urls": known,
        "microbench": { "requests": n, "mean_ns_per_match": per_ns, "blocked": blocked },
    });
    (e2, stats)
}

fn pct(v: &mut Vec<f64>, p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() - 1) as f64 * p).round() as usize]
}

fn bench(fx: &Fixture, engine: Engine) -> Value {
    note("S2 bench");
    let udf = crate::fresh_udf("s2-bench");
    let env = host::create_env(&udf, &host::EnvOpts { tracking_prevention: true, ..Default::default() });
    let engine = Rc::new(engine);
    let match_ns: Rc<RefCell<Vec<f64>>> = Default::default();
    let modes = ["none", "noop", "engine"];
    let mut views = vec![];
    for (i, m) in modes.iter().enumerate() {
        let hwnd = host::create_window(&format!("S2 bench — {m}"), 600, 500);
        unsafe {
            let _ = windows::Win32::UI::WindowsAndMessaging::SetWindowPos(
                hwnd, None, 20 + i as i32 * 610, 40, 600, 500,
                windows::Win32::UI::WindowsAndMessaging::SWP_NOZORDER,
            );
        }
        let ctrl = host::create_controller(&env, hwnd, "default", false);
        host::fit(&ctrl, hwnd);
        let wv = host::webview(&ctrl);
        if *m != "none" {
            let w22: ICoreWebView2_22 = wv.cast().expect("22");
            unsafe {
                w22.AddWebResourceRequestedFilterWithRequestSourceKinds(
                    w!("*"),
                    COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
                    COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_ALL,
                )
                .expect("filter");
            }
            let use_engine = *m == "engine";
            let (engine, match_ns, env2) = (engine.clone(), match_ns.clone(), env.clone());
            let mut tok = 0i64;
            let h = WebResourceRequestedEventHandler::create(Box::new(move |_w, args| {
                let Some(a) = args else { return Ok(()) };
                let req = unsafe { a.Request()? };
                let mut p = PWSTR::null();
                unsafe { req.Uri(&mut p)? };
                let uri = host::take(p);
                if use_engine {
                    let mut ctx = COREWEBVIEW2_WEB_RESOURCE_CONTEXT(0);
                    unsafe { a.ResourceContext(&mut ctx)? };
                    let t = Instant::now();
                    let blocked = Request::new(&uri, "http://localhost/bench/page.html", adblock_type(ctx.0), "GET")
                        .map(|r| engine.check_network_request(&r).should_block())
                        .unwrap_or(false);
                    match_ns.borrow_mut().push(t.elapsed().as_nanos() as f64);
                    if blocked {
                        let resp = host::make_response(&env2, 403, "Blocked", "", b"");
                        unsafe { a.SetResponse(&resp)? };
                    }
                }
                Ok(())
            }));
            unsafe { wv.add_WebResourceRequested(&h, &mut tok).expect("handler") };
        }
        views.push((m.to_string(), ctrl, wv, hwnd));
    }

    let base = format!("http://localhost:{}", fx.http_port);
    let runs = 14;
    let mut wall: Vec<Vec<f64>> = vec![vec![]; modes.len()];
    let mut load: Vec<Vec<f64>> = vec![vec![]; modes.len()];
    let mut resources = vec![0u64; modes.len()];
    for run in 0..runs {
        for (i, (m, _c, wv, _h)) in views.iter().enumerate() {
            let url = format!("{base}/bench/page.html?run={run}-{m}");
            let t = Instant::now();
            let nav = host::navigate(wv, &url, host::T);
            let ms = t.elapsed().as_secs_f64() * 1e3;
            let perf = host::exec_json(wv, "window.__perf || null");
            if run >= 2 && nav.map(|n| n.ok).unwrap_or(false) {
                wall[i].push(ms);
                if let Some(l) = perf["load"].as_f64() {
                    load[i].push(l);
                }
                resources[i] = perf["resources"].as_u64().unwrap_or(0);
            }
        }
    }
    let mut out = serde_json::Map::new();
    for (i, m) in modes.iter().enumerate() {
        let n = wall[i].len();
        out.insert(
            m.to_string(),
            json!({
                "samples": n,
                "resources_per_page": resources[i],
                "wall_ms_median": pct(&mut wall[i].clone(), 0.5),
                "wall_ms_p95": pct(&mut wall[i].clone(), 0.95),
                "load_event_ms_median": pct(&mut load[i].clone(), 0.5),
                "load_event_ms_p95": pct(&mut load[i].clone(), 0.95),
            }),
        );
    }
    let mut mn = match_ns.borrow().clone();
    let none_med = out["none"]["load_event_ms_median"].as_f64().unwrap_or(f64::NAN);
    let noop_med = out["noop"]["load_event_ms_median"].as_f64().unwrap_or(f64::NAN);
    let eng_med = out["engine"]["load_event_ms_median"].as_f64().unwrap_or(f64::NAN);
    let reqs = (resources[0] + 1) as f64;
    let summary = json!({
        "intercept_overhead_ms_per_page": noop_med - none_med,
        "intercept_overhead_ms_per_request": (noop_med - none_med) / reqs,
        "engine_extra_ms_per_page": eng_med - noop_med,
        "total_overhead_pct": (eng_med - none_med) / none_med * 100.0,
        "engine_match_ns_p50": pct(&mut mn, 0.5),
        "engine_match_ns_p99": pct(&mut mn, 0.99),
        "engine_matches_recorded": mn.len(),
        "note": "Loopback fixture: absolute page-load times are tiny, so percentages overstate real-world overhead; per-request cost is the transferable number.",
    });
    for (_m, c, _w, h) in views {
        host::close(c);
        host::destroy_window(h);
    }
    json!({ "modes": out, "summary": summary })
}

pub fn run() -> Value {
    let fx = fixture::start(router(), None);
    note(&format!("fixture on http://localhost:{}", fx.http_port));
    let (engine, engine_stats) = build_engine();
    note(&format!("engine: {engine_stats}"));
    let version = {
        let udf = crate::fresh_udf("s2-version");
        let env = host::create_env(&udf, &host::EnvOpts::default());
        host::browser_version(&env)
    };
    let legacy = coverage(&fx, "legacy-filter");
    let kinds = coverage(&fx, "source-kinds");
    let bench = bench(&fx, engine);
    json!({
        "spike": "S2 interception",
        "runtime_version": version,
        "coverage_legacy_filter": legacy,
        "coverage_source_kinds": kinds,
        "adblock_engine": engine_stats,
        "bench": bench,
    })
}
