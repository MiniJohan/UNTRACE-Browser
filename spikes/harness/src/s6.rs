//! S6 - Third-party cookies and tracking prevention.
//! Ground truth = the Cookie header the fixture receives on third-party requests.
//! (a) baseline, (b) DevTools `Network.setCookieControls`, (c) whether (b) carries over to a
//! second view in the same profile, (d) Edge tracking prevention levels against a domain on
//! Edge's tracker lists (several known tracker hosts over plain HTTP, mapped locally - nothing leaves the machine).

use std::{sync::Arc, time::Duration};

use serde_json::{json, Value};
use webview2_com::Microsoft::Web::WebView2::Win32::*;
use windows::core::*;

use crate::{
    fixture::{Req, Resp},
    host, kit, note, pump,
};

const TOP: &str = r#"<!doctype html><title>top</title><body>
<img src="https://{T}/s6/pixel.png?from={S}">
<iframe src="https://{T}/s6/frame.html?from={S}"></iframe>
<script>
  addEventListener('message', e => { document.title = 'got:' + e.data; });
  setTimeout(() => { if (!document.title.startsWith('got:')) document.title = 'got:NOFRAME'; }, 4000);
</script></body>"#;

const TRACKERS: &[&str] = &[
    "b.scorecardresearch.com", "pixel.quantserve.com", "ib.adnxs.com", "static.criteo.net",
    "cdn.taboola.com", "script.hotjar.com", "www.google-analytics.com", "connect.facebook.net",
];

const FRAME: &str = r#"<!doctype html><script>
  document.cookie = 'jsid=JS1; SameSite=None; Secure; path=/; max-age=3600';
  let sa = 'n/a';
  try { sa = String(document.hasStorageAccess ? 'api' : 'none'); } catch (e) {}
  parent.postMessage(document.cookie || '(none)', '*');
</script>"#;

fn router() -> crate::fixture::Router {
    Arc::new(|r: &Req| {
        let q = r.path.split('?').nth(1).unwrap_or("");
        let get = |k: &str| q.split('&').find_map(|kv| kv.strip_prefix(&format!("{k}="))).unwrap_or("").to_string();
        match r.route() {
            "/s6/top.html" => Resp::html(TOP.replace("{T}", &get("t")).replace("{S}", &r.host)),
            "/s6/frame.html" => Resp::html(FRAME).with("Set-Cookie", "hdr=H1; SameSite=None; Secure; Path=/; Max-Age=3600"),
            "/s6/tp.html" => Resp::html(
                TRACKERS
                    .iter()
                    .map(|t| t.to_string())
                    .chain(Some(format!("site-c{}", kit::sfx()))) // neutral third party (control)
                    .map(|t| format!("<img src=\"http://{t}/s6/pixel.png\"><script src=\"http://{t}/s6/t.js\"></script>"))
                    .collect::<String>(),
            ),
            "/s6/pixel.png" => Resp::png().with("Set-Cookie", "pix=P1; SameSite=None; Secure; Path=/; Max-Age=3600"),
            _ => Resp::text("ok"),
        }
    })
}

struct Outcome {
    title_a: String,
    title_b: String,
    tracker_requests: Vec<Value>,
}

/// Visit site A then site B, both embedding `tracker`. Returns what the tracker saw.
fn visit_pair(wv: &ICoreWebView2, k: &kit::Kit, a: &str, b: &str, tracker: &str) -> Outcome {
    let mark = k.fx.mark();
    let mut titles = vec![];
    for site in [a, b] {
        let _ = host::navigate(wv, &format!("https://{site}/s6/top.html?t={tracker}"), host::T);
        pump::until(Duration::from_secs(8), || host::exec(wv, "document.title").starts_with("\"got:"));
        titles.push(host::exec(wv, "document.title"));
    }
    let tracker_requests = k
        .fx
        .since(mark)
        .iter()
        .filter(|r| r.host == tracker)
        .map(|r| json!({ "path": r.path, "cookie_header": r.header("cookie") }))
        .collect();
    Outcome { title_a: titles[0].clone(), title_b: titles[1].clone(), tracker_requests }
}

fn outcome_json(o: Outcome) -> Value {
    let on_b: Vec<&Value> = o
        .tracker_requests
        .iter()
        .filter(|r| r["path"].as_str().map(|p| p.contains("from=site-b") || p.contains("from=site-d")).unwrap_or(false))
        .collect();
    let cookies_sent_cross_site = on_b.iter().any(|r| !r["cookie_header"].is_null());
    json!({
        "frame_title_on_site_a": o.title_a,
        "frame_title_on_site_b": o.title_b,
        "third_party_cookies_sent_on_second_site": cookies_sent_cross_site,
        "tracker_requests": o.tracker_requests,
    })
}

fn view(env: &ICoreWebView2Environment, hwnd: windows::Win32::Foundation::HWND, profile: &str) -> (ICoreWebView2Controller, ICoreWebView2) {
    let c = host::create_controller(env, hwnd, profile, false);
    let w = host::webview(&c);
    kit::prepare(&w);
    (c, w)
}

fn set_tp(wv: &ICoreWebView2, level: COREWEBVIEW2_TRACKING_PREVENTION_LEVEL) -> i32 {
    let p3: ICoreWebView2Profile3 = kit::profile(wv).cast().expect("Profile3");
    let mut back = COREWEBVIEW2_TRACKING_PREVENTION_LEVEL(-1);
    unsafe {
        p3.SetPreferredTrackingPreventionLevel(level).expect("set tp");
        let _ = p3.PreferredTrackingPreventionLevel(&mut back);
    }
    back.0
}

pub fn run() -> Value {
    let k = kit::start(&["site-a", "site-b", "site-c", "site-d", "tracker"], TRACKERS, router());
    let (a, b, c, d, t) = (k.host("site-a"), k.host("site-b"), k.host("site-c"), k.host("site-d"), k.host("tracker"));
    let udf = crate::fresh_udf("s6");
    let env = host::create_env(&udf, &host::EnvOpts { args: k.env_args(""), tracking_prevention: true, ..Default::default() });
    let hwnd = host::create_window("S6 third-party cookies", 900, 650);

    note("S6a baseline");
    let (c1, w1) = view(&env, hwnd, "baseline");
    let tp1 = set_tp(&w1, COREWEBVIEW2_TRACKING_PREVENTION_LEVEL_BALANCED);
    let baseline = outcome_json(visit_pair(&w1, &k, &a, &b, &t));

    note("S6b Network.setCookieControls");
    let (c2, w2) = view(&env, hwnd, "cdp");
    let net_enable = host::cdp(&w2, "Network.enable", "{}");
    let full = host::cdp(
        &w2,
        "Network.setCookieControls",
        r#"{"enableThirdPartyCookieRestriction":true,"disableThirdPartyCookieMetadata":true,"disableThirdPartyCookieHeuristics":true}"#,
    );
    let minimal = if full.is_err() {
        Some(host::cdp(&w2, "Network.setCookieControls", r#"{"enableThirdPartyCookieRestriction":true}"#))
    } else {
        None
    };
    let cdp_result = outcome_json(visit_pair(&w2, &k, &a, &b, &t));

    note("S6c same profile, second view without the CDP call");
    let (c3, w3) = view(&env, hwnd, "cdp");
    let carry = outcome_json(visit_pair(&w3, &k, &c, &d, &t));
    // And the first view again after other navigations (does the control persist per view?)
    let persist = outcome_json(visit_pair(&w2, &k, &c, &d, &t));

    note("S6d Edge tracking prevention vs known tracker hosts (plain HTTP, mapped locally)");
    let mut tp = serde_json::Map::new();
    for (name, level) in [
        ("none", COREWEBVIEW2_TRACKING_PREVENTION_LEVEL_NONE),
        ("basic", COREWEBVIEW2_TRACKING_PREVENTION_LEVEL_BASIC),
        ("balanced", COREWEBVIEW2_TRACKING_PREVENTION_LEVEL_BALANCED),
        ("strict", COREWEBVIEW2_TRACKING_PREVENTION_LEVEL_STRICT),
    ] {
        let (cc, ww) = view(&env, hwnd, &format!("tp-{name}"));
        let back = set_tp(&ww, level);
        let mark = k.fx.mark();
        let pmark = k.px.events().len();
        let _ = host::navigate(&ww, &format!("http://{a}/s6/tp.html"), host::T);
        pump::sleep(Duration::from_secs(4));
        let reached: std::collections::BTreeSet<String> =
            k.fx.since(mark).iter().filter(|r| TRACKERS.contains(&r.host.as_str())).map(|r| r.host.clone()).collect();
        let via_proxy: std::collections::BTreeSet<String> = k.px.events()[pmark..]
            .iter()
            .filter(|e| TRACKERS.iter().any(|t| e.target.contains(t)))
            .map(|e| format!("{} {}", e.kind, e.target))
            .collect();
        let neutral = k.fx.since(mark).iter().any(|r| r.host == c && r.route() == "/s6/pixel.png");
        tp.insert(
            name.into(),
            json!({ "level_read_back": back, "trackers_reached": reached, "neutral_third_party_loaded": neutral, "proxy_saw": via_proxy }),
        );
        host::close(cc);
    }
    let refused: Vec<String> = k.px.events().iter().filter(|e| e.kind == "refused-unmapped").map(|e| e.target.clone()).collect();
    for c in [c1, c2, c3] {
        host::close(c);
    }
    host::destroy_window(hwnd);
    json!({
        "spike": "S6 third-party cookies",
        "baseline_balanced": { "level_read_back": tp1, "result": baseline },
        "cdp_set_cookie_controls": {
            "network_enable": format!("{net_enable:?}"),
            "call_full": format!("{full:?}"),
            "call_minimal": format!("{minimal:?}"),
            "result_same_view": cdp_result,
            "result_same_view_later_sites": persist,
            "result_second_view_same_profile": carry,
        },
        "edge_tracking_prevention_vs_known_trackers": tp,
        "proxy_refused_hosts": refused,
    })
}

