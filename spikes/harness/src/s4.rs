//! S4 - Cosmetic filtering vehicles. Can UNTRACE hide elements on pages with a strict CSP
//! and inside cross-origin iframes, early enough to avoid a visible flash?
//! Vehicles:
//!   a1  main-world document-start script, sync XHR to a locally answered endpoint -> adoptedStyleSheets
//!   a2  same, but a <style> element
//!   a3  main-world script with the CSS embedded (no fetch) -> adoptedStyleSheets
//!   a4  like a3 but registered per navigation from NavigationStarting / FrameNavigationStarting (race test)
//!   b1  DevTools isolated world (Page.addScriptToEvaluateOnNewDocument worldName) + XHR + <style>
//!   c1  MV3 extension: static manifest CSS
//!   c2  MV3 extension: content script fetches CSS, background inserts it with chrome.scripting.insertCSS

use std::{
    sync::{mpsc, Arc},
    time::Duration,
};

use serde_json::{json, Value};
use webview2_com::{Microsoft::Web::WebView2::Win32::*, *};
use windows::core::*;

use crate::{
    fixture::{Req, Resp},
    host, kit, note, pump,
};

const CSS: &str = ".ad-banner { display: none !important; }";

fn csp(frame_host: &str) -> String {
    format!(
        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-src https://{frame_host}; report-uri /s4/csp-report"
    )
}

fn page(body_extra: &str) -> String {
    format!(
        r#"<!doctype html><html><head><meta charset=utf-8><title>s4</title></head><body>
<div class="ad-banner" id="ad">AD (dynamic rule)</div><script src="/s4/early.js"></script>
<div class="ad-banner-static">AD (static rule)</div>
<p class="content">content</p>{body_extra}
<script src="/s4/probe.js"></script></body></html>"#
    )
}

const EARLY_JS: &str = "window.__early = getComputedStyle(document.getElementById('ad')).display;";
const PROBE_JS: &str = r#"(function () {
  addEventListener('message', e => { if (e.data && e.data.frame) window.__frame = e.data.frame; });
  setTimeout(() => {
    const q = s => { const el = document.querySelector(s); return el ? getComputedStyle(el).display : 'missing'; };
    const r = { dyn: q('.ad-banner'), stat: q('.ad-banner-static'), early_dyn: window.__early || null };
    if (window.top !== window) parent.postMessage({ frame: r }, '*'); else window.__top = r;
  }, 1500);
})();"#;

/// Main-world bootstrap: sync XHR to the local endpoint, then apply.
fn bootstrap_xhr(apply_style_element: bool) -> String {
    let apply = if apply_style_element {
        "const add = () => { const s = document.createElement('style'); s.textContent = css; document.documentElement.appendChild(s); };
         if (document.documentElement) add(); else new MutationObserver((m, o) => { if (document.documentElement) { o.disconnect(); add(); } }).observe(document, { childList: true });"
    } else {
        "const sh = new CSSStyleSheet(); sh.replaceSync(css); document.adoptedStyleSheets = [...document.adoptedStyleSheets, sh];"
    };
    format!(
        "(() => {{ try {{ const x = new XMLHttpRequest(); x.open('GET', 'https://cosmetic.untrace.invalid/css?u=' + encodeURIComponent(location.href), false); x.send(); const css = x.responseText; {apply} }} catch (e) {{ window.__cosErr = String(e); }} }})();"
    )
}

fn bootstrap_embedded(host_filter: Option<&str>) -> String {
    let cond = host_filter.map(|h| format!("if (location.hostname !== '{h}') return;")).unwrap_or_default();
    format!(
        "(() => {{ {cond} try {{ const sh = new CSSStyleSheet(); sh.replaceSync({css:?}); document.adoptedStyleSheets = [...document.adoptedStyleSheets, sh]; }} catch (e) {{ window.__cosErr = String(e); }} }})();",
        css = CSS
    )
}

fn intercept_cosmetic_endpoint(env: &ICoreWebView2Environment, wv: &ICoreWebView2) {
    let w22: ICoreWebView2_22 = wv.cast().expect("22");
    unsafe {
        w22.AddWebResourceRequestedFilterWithRequestSourceKinds(
            w!("https://cosmetic.untrace.invalid/*"),
            COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
            COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_ALL,
        )
        .expect("filter");
    }
    let env = env.clone();
    let mut tok = 0i64;
    let h = WebResourceRequestedEventHandler::create(Box::new(move |_w, args| {
        if let Some(a) = args {
            let resp = host::make_response(
                &env,
                200,
                "OK",
                "Content-Type: text/css\r\nAccess-Control-Allow-Origin: *",
                CSS.as_bytes(),
            );
            unsafe { a.SetResponse(&resp)? };
        }
        Ok(())
    }));
    unsafe { wv.add_WebResourceRequested(&h, &mut tok).expect("handler") };
}

fn dynamic_registration(wv: &ICoreWebView2) {
    // On every top-level and frame navigation, register a host-specific script (async, no wait).
    let make = |wv: ICoreWebView2| {
        move |uri: String| {
            let host = uri.split("://").nth(1).and_then(|r| r.split(['/', ':']).next()).unwrap_or("").to_string();
            let js = bootstrap_embedded(Some(&host));
            let h = AddScriptToExecuteOnDocumentCreatedCompletedHandler::create(Box::new(|_hr, _id| Ok(())));
            unsafe {
                let _ = wv.AddScriptToExecuteOnDocumentCreated(&HSTRING::from(js), &h);
            }
        }
    };
    let top = make(wv.clone());
    let frame = make(wv.clone());
    let mut t1 = 0i64;
    let mut t2 = 0i64;
    let h1 = NavigationStartingEventHandler::create(Box::new(move |_w, args| {
        if let Some(a) = args {
            let mut p = PWSTR::null();
            unsafe { a.Uri(&mut p)? };
            top(host::take(p));
        }
        Ok(())
    }));
    let h2 = NavigationStartingEventHandler::create(Box::new(move |_w, args| {
        if let Some(a) = args {
            let mut p = PWSTR::null();
            unsafe { a.Uri(&mut p)? };
            frame(host::take(p));
        }
        Ok(())
    }));
    unsafe {
        wv.add_NavigationStarting(&h1, &mut t1).expect("nav starting");
        wv.add_FrameNavigationStarting(&h2, &mut t2).expect("frame nav starting");
    }
}

fn write_extension(dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).expect("ext dir");
    std::fs::write(
        dir.join("manifest.json"),
        r#"{
  "manifest_version": 3, "name": "UNTRACE cosmetic spike", "version": "0.0.1",
  "permissions": ["scripting"], "host_permissions": ["<all_urls>"],
  "background": { "service_worker": "bg.js" },
  "content_scripts": [{ "matches": ["<all_urls>"], "all_frames": true, "match_about_blank": true,
                        "run_at": "document_start", "css": ["static.css"], "js": ["cs.js"] }]
}"#,
    )
    .unwrap();
    std::fs::write(dir.join("static.css"), ".ad-banner-static { display: none !important; }").unwrap();
    std::fs::write(
        dir.join("cs.js"),
        r#"fetch('https://cosmetic.untrace.invalid/css?u=' + encodeURIComponent(location.href))
  .then(r => r.text())
  .then(css => chrome.runtime.sendMessage({ css }))
  .catch(e => chrome.runtime.sendMessage({ err: String(e) }));"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("bg.js"),
        r#"chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.css && sender.tab) {
    chrome.scripting.insertCSS({ target: { tabId: sender.tab.id, frameIds: [sender.frameId] }, css: msg.css })
      .catch(e => console.log('insertCSS failed', e));
  }
});"#,
    )
    .unwrap();
}

fn add_extension(wv: &ICoreWebView2, dir: &std::path::Path) -> String {
    let p7: ICoreWebView2Profile7 = kit::profile(wv).cast().expect("Profile7");
    let (tx, rx) = mpsc::channel();
    let h = ProfileAddBrowserExtensionCompletedHandler::create(Box::new(move |hr, ext| {
        let id = ext.map(|e| {
            let mut p = PWSTR::null();
            unsafe {
                let _ = e.Id(&mut p);
            }
            host::take(p)
        });
        let _ = tx.send(format!("{:?} id={:?}", hr.map_err(|e| e.message()), id));
        Ok(())
    }));
    unsafe {
        if let Err(e) = p7.AddBrowserExtension(&HSTRING::from(dir.as_os_str()), &h) {
            return format!("call failed: {e:?}");
        }
    }
    pump::wait(&rx, host::T).unwrap_or_else(|| "timeout".into())
}

fn measure(wv: &ICoreWebView2, k: &kit::Kit, path: &str) -> Value {
    let mark = k.fx.mark();
    let url = format!("https://{}{path}", k.host("site-a"));
    let nav = host::navigate(wv, &url, host::T);
    pump::until(Duration::from_secs(6), || {
        let v = host::exec_json(wv, "({ top: window.__top || null, frame: window.__frame || null })");
        !v["top"].is_null() && !v["frame"].is_null()
    });
    let v = host::exec_json(wv, "({ top: window.__top || null, frame: window.__frame || null, err: window.__cosErr || null })");
    let reports = k.fx.since(mark).iter().filter(|r| r.route() == "/s4/csp-report").count();
    json!({ "nav_ok": nav.map(|n| n.ok), "top": v["top"], "frame": v["frame"], "main_world_error": v["err"], "csp_reports": reports })
}

pub fn run() -> Value {
    let sfx = kit::sfx();
    let b_host = format!("site-b{sfx}");
    let bh = b_host.clone();
    let router: crate::fixture::Router = Arc::new(move |r: &Req| match r.route() {
        "/s4/strict.html" => Resp::html(page(&format!("<iframe src=\"https://{bh}/s4/frame-strict.html\"></iframe>")))
            .with("Content-Security-Policy", csp(&bh)),
        "/s4/plain.html" => Resp::html(page(&format!("<iframe src=\"https://{bh}/s4/frame-plain.html\"></iframe>"))),
        "/s4/frame-strict.html" => Resp::html(page("")).with("Content-Security-Policy", csp(&bh)),
        "/s4/frame-plain.html" => Resp::html(page("")),
        "/s4/early.js" => Resp::js(EARLY_JS),
        "/s4/probe.js" => Resp::js(PROBE_JS),
        _ => Resp::text("ok"),
    });
    let k = kit::start(&["site-a", "site-b"], &[], router);
    let hwnd = host::create_window("S4 cosmetic vehicles", 900, 650);
    let mut out = serde_json::Map::new();

    // Vehicles (a*) and (b*): environment without extensions.
    let udf = crate::fresh_udf("s4");
    let env = host::create_env(&udf, &host::EnvOpts { args: k.env_args(""), tracking_prevention: true, ..Default::default() });

    let baseline = {
        let c = host::create_controller(&env, hwnd, "none", false);
        let w = host::webview(&c);
        kit::prepare(&w);
        let r = json!({ "plain": measure(&w, &k, "/s4/plain.html"), "strict": measure(&w, &k, "/s4/strict.html") });
        host::close(c);
        r
    };
    out.insert("baseline_no_vehicle".into(), baseline);

    for v in ["a1", "a2", "a3", "a4", "b1"] {
        note(&format!("S4 vehicle {v}"));
        let c = host::create_controller(&env, hwnd, &format!("v-{v}"), false);
        let w = host::webview(&c);
        kit::prepare(&w);
        let setup = match v {
            "a1" => { intercept_cosmetic_endpoint(&env, &w); format!("{:?}", host::add_init_script(&w, &bootstrap_xhr(false))) }
            "a2" => { intercept_cosmetic_endpoint(&env, &w); format!("{:?}", host::add_init_script(&w, &bootstrap_xhr(true))) }
            "a3" => format!("{:?}", host::add_init_script(&w, &bootstrap_embedded(None))),
            "a4" => { dynamic_registration(&w); "dynamic".into() }
            _ => {
                intercept_cosmetic_endpoint(&env, &w);
                let params = json!({ "source": bootstrap_xhr(true), "worldName": "untrace", "runImmediately": true }).to_string();
                format!("{:?}", host::cdp(&w, "Page.addScriptToEvaluateOnNewDocument", &params))
            }
        };
        let r = json!({ "setup": setup, "plain": measure(&w, &k, "/s4/plain.html"), "strict": measure(&w, &k, "/s4/strict.html") });
        out.insert(v.into(), r);
        host::close(c);
    }
    drop(env);

    // Vehicles (c*): environment with extensions enabled.
    note("S4 vehicle c (extension)");
    let udf_x = crate::fresh_udf("s4x");
    let ext_dir = crate::udf_root().join(format!("ext-s4-{}", std::process::id()));
    write_extension(&ext_dir);
    let envx = host::create_env(
        &udf_x,
        &host::EnvOpts { args: k.env_args(""), tracking_prevention: true, extensions: true, ..Default::default() },
    );
    let c = host::create_controller(&envx, hwnd, "ext", false);
    let w = host::webview(&c);
    kit::prepare(&w);
    intercept_cosmetic_endpoint(&envx, &w);
    let added = add_extension(&w, &ext_dir);
    pump::sleep(Duration::from_millis(500));
    let r = json!({ "add_extension": added, "plain": measure(&w, &k, "/s4/plain.html"), "strict": measure(&w, &k, "/s4/strict.html") });
    out.insert("c_extension".into(), r);
    host::close(c);
    host::destroy_window(hwnd);

    json!({
        "spike": "S4 cosmetic vehicles",
        "legend": {
            "dyn": "computed display of .ad-banner after 1.5 s (none = hidden by dynamic rule)",
            "stat": "computed display of .ad-banner-static (only the extension's static CSS targets it)",
            "early_dyn": "display of .ad-banner from a page script placed right after the element (none = hidden before first paint, no flash)",
            "csp_reports": "CSP violation reports received by the fixture",
        },
        "vehicles": out,
    })
}
