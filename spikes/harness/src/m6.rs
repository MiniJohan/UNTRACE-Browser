//! M6 pre-check — the cost and correctness of the cosmetic document-start script (D-015) built
//! from the bundled EasyList + EasyPrivacy by `untrace_filter::cosmetic`, in the real engine.
//!
//! Variants: no script (baseline), "observe" (generic rules applied by observed class/id),
//! "all" (every generic rule in one stylesheet per frame). A heavy page (3,000 elements,
//! 800 distinct classes) with 8 cross-origin frames, all under a strict CSP. Each variant runs
//! `ROUNDS` times in a fresh view; medians are reported.

use std::{sync::Arc, time::Duration};

use serde_json::{json, Value};
use untrace_filter::{
    catalog::ListId,
    cosmetic::{CosmeticRules, GenericMode, ScriptOptions},
    engine::Source,
};

use webview2_com::{Microsoft::Web::WebView2::Win32::*, *};
use windows::core::*;

use crate::{
    fixture::{Req, Resp},
    host, kit, note, pump,
};

/// TEST-ONLY: accept the fixture's self-signed certificate for `.test` names and the one real
/// host name the spike proxy maps to the fixture.
fn allow_certs(wv: &ICoreWebView2, extra: String) {
    let wv14: ICoreWebView2_14 = wv.cast().expect("WebView2_14");
    let mut token = 0i64;
    let h = ServerCertificateErrorDetectedEventHandler::create(Box::new(move |_s, args| {
        if let Some(a) = args {
            let mut p = PWSTR::null();
            unsafe { a.RequestUri(&mut p)? };
            let uri = host::take(p);
            let h = uri.split("://").nth(1).and_then(|r| r.split(['/', ':']).next()).unwrap_or("").to_string();
            let ok = h.ends_with(".test") || h == extra;
            unsafe {
                a.SetAction(if ok {
                    COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_ALWAYS_ALLOW
                } else {
                    COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_CANCEL
                })?;
            }
        }
        Ok(())
    }));
    unsafe { wv14.add_ServerCertificateErrorDetected(&h, &mut token).expect("cert handler") };
}

const ROUNDS: usize = 9;
const FRAMES: usize = 8;
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-src https:; report-uri /csp-report";

fn median(mut v: Vec<f64>) -> f64 {
    v.retain(|x| x.is_finite());
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// The page's own check: computed display of the targets, the script's stats, load timing, and
/// the frames' reports (posted to the parent).
const CHECK_JS: &str = r#"
const targets = { generic_class: 'g-class', generic_id: 'g-id', specific: 's-target', control: 'control' };
const frames = [];
addEventListener('message', (e) => { if (e.data && e.data.m6) frames.push(e.data.m6); });
const report = () => {
  const r = {};
  for (const [k, id] of Object.entries(targets)) { const el = document.getElementById(id) || document.querySelector('[data-t="' + id + '"]'); r[k] = el ? getComputedStyle(el).display : 'missing'; }
  const n = performance.getEntriesByType('navigation')[0];
  window.__m6 = JSON.stringify({ hidden: r, stats: self.__untraceCosmetic || null, load: n ? n.loadEventEnd : null, dcl: n ? n.domContentLoadedEventEnd : null, frames });
  document.title = 'm6-done';
};
addEventListener('load', () => setTimeout(report, 1500));
"#;

const FRAME_JS: &str = r#"
addEventListener('load', () => setTimeout(() => {
  const el = document.getElementById('f-ad');
  parent.postMessage({ m6: { hidden: el ? getComputedStyle(el).display : 'missing', stats: self.__untraceCosmetic || null } }, '*');
}, 300));
"#;

fn page(ad_class: &str, ad_id: &str, specific: &str, frame_hosts: &[String]) -> String {
    let mut body = String::new();
    for i in 0..3000 {
        body.push_str(&format!("<div class=\"c{} k{}\"><span class=\"t{}\">x</span></div>", i % 800, i % 37, i % 211));
    }
    let frames: String = frame_hosts
        .iter()
        .map(|h| format!("<iframe src=\"https://{h}/m6/frame.html\" width=50 height=50></iframe>"))
        .collect();
    format!(
        "<!doctype html><html><head><meta charset=utf-8><title>m6</title><script src=\"/m6/check.js\"></script></head><body>\
         <div id=\"g-class-wrap\"><div id=\"g-class\" class=\"{ad_class}\">ad</div></div>\
         <div id=\"{ad_id}\" data-t=\"g-id\">ad</div>\
         <div id=\"s-target\" {specific}>specific</div><div id=\"control\" class=\"content\">content</div>\
         {body}{frames}</body></html>"
    )
}

pub fn run() -> Value {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/untrace-filter/lists");
    let easylist = std::fs::read_to_string(root.join("easylist.txt")).expect("easylist");
    let easyprivacy = std::fs::read_to_string(root.join("easyprivacy.txt")).expect("easyprivacy");
    let t = std::time::Instant::now();
    let rules = CosmeticRules::build(&[
        Source { id: ListId::EasyList, text: &easylist },
        Source { id: ListId::EasyPrivacy, text: &easyprivacy },
    ]);
    let build_ms = t.elapsed().as_secs_f64() * 1e3;

    // Targets: a generic class rule, a generic id rule, and a site-specific rule for a real host
    // that the spike proxy maps to the fixture.
    let ad_class = rules.simple_classes.iter().find(|c| c.contains("ad")).cloned().unwrap_or_default();
    let ad_id = rules.simple_ids.iter().find(|c| c.contains("ad")).cloned().unwrap_or_default();
    let (specific_host, specific_sel) = rules
        .hosts
        .iter()
        .filter(|(h, r)| !h.contains('*') && h.matches('.').count() == 1 && r.unhide.is_empty())
        .find_map(|(h, r)| {
            r.hide
                .iter()
                .find(|s| s.starts_with('.') && s[1..].chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
                .map(|s| (h.clone(), s[1..].to_string()))
        })
        .expect("a host with a simple class rule");
    note(&format!("targets: .{ad_class}  #{ad_id}  {specific_host} .{specific_sel}"));

    let suffix = kit::sfx();
    let labels: Vec<String> = (0..FRAMES).map(|i| format!("f{i}")).collect();
    let label_refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    let frame_hosts: Vec<String> = labels.iter().map(|l| format!("{l}{suffix}")).collect();
    let (ac, ai, ss, fh) = (ad_class.clone(), ad_id.clone(), specific_sel.clone(), frame_hosts.clone());
    let kit = kit::start(
        &label_refs,
        &[specific_host.as_str()],
        Arc::new(move |r: &Req| match r.route() {
            "/m6/page.html" => Resp::html(page(&ac, &ai, &format!("class=\"{ss}\""), &fh))
                .with("Content-Security-Policy", CSP),
            "/m6/check.js" => Resp::js(CHECK_JS),
            "/m6/frame.js" => Resp::js(FRAME_JS),
            "/m6/frame.html" => Resp::html(format!(
                "<!doctype html><html><head><meta charset=utf-8><script src=\"/m6/frame.js\"></script></head><body><div id=\"f-ad\" class=\"{ac}\">ad</div>{}</body></html>",
                (0..300).map(|i| format!("<p class=\"p{}\">x</p>", i % 50)).collect::<String>()
            ))
            .with("Content-Security-Policy", CSP),
            "/csp-report" => Resp::text("ok"),
            _ => Resp::text("ok"),
        }),
    );
    let csp_mark = kit.fx.mark();

    let script = |g: GenericMode, embed: bool| {
        rules.script(&ScriptOptions {
            generic: g,
            off_sites: vec![],
            debug: true,
            embed_site_rules: embed,
        })
    };
    let observe = script(GenericMode::Observe, true);
    let split = script(GenericMode::Observe, false);
    let site = untrace_filter::cosmetic::site_script(
        &specific_host,
        &rules.site_css(&specific_host).unwrap_or_default(),
    );
    let all = script(GenericMode::All, true);

    let parse_only = rules.script(&ScriptOptions {
        generic: GenericMode::Observe,
        off_sites: vec!["test".into(), specific_host.clone()],
        debug: true,
        embed_site_rules: true,
    });
    let tiny = "(() => { self.__untraceCosmetic = { setupMs: 0, started: performance.now() }; })();".to_string();
    // The same 0.7 MB of source inside a function that is never called: the engine only has to
    // scan it, not build its strings.
    let names = ["baseline", "tiny_script", "observe_one_script", "observe_split", "parse_only"];
    let scripts: [Option<&String>; 5] = [None, Some(&tiny), Some(&observe), Some(&split), Some(&parse_only)];
    let _ = &all;
    let udf = crate::fresh_udf("m6");
    let env = host::create_env(&udf, &host::EnvOpts { args: kit.env_args(""), ..Default::default() });
    let hwnd = host::create_window("M6", 1000, 700);
    let mut runs: Vec<Vec<Value>> = vec![Vec::new(); 5];
    // Warm-up load, not counted (first navigation of a fresh profile is slow).
    {
        let c = host::create_controller(&env, hwnd, "default", false);
        let wv = host::webview(&c);
        allow_certs(&wv, specific_host.clone());
        let _ = host::navigate(&wv, &format!("https://{specific_host}/m6/page.html?warm"), host::T);
        host::wait_title(&wv, "m6-done", Duration::from_secs(20));
        host::close(c);
    }
    for round in 0..ROUNDS {
        for k in 0..5 {
            let v = (round + k) % 5;
            let c = host::create_controller(&env, hwnd, "default", false);
            let wv = host::webview(&c);
            allow_certs(&wv, specific_host.clone());
            if let Some(js) = scripts[v] {
                host::add_init_script(&wv, js).expect("init script");
            }
            if names[v] == "observe_split" {
                host::add_init_script(&wv, &site).expect("site script");
            }
            let url = format!("https://{specific_host}/m6/page.html?r={round}&v={v}");
            let nav = host::navigate(&wv, &url, host::T);
            let done = host::wait_title(&wv, "m6-done", Duration::from_secs(20));
            let raw = host::exec_json(&wv, "window.__m6 || null");
            let r: Value = raw.as_str().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
            runs[v].push(json!({ "nav": format!("{nav:?}"), "done": done, "result": r }));
            host::close(c);
            pump::sleep(Duration::from_millis(200));
        }
    }
    host::destroy_window(hwnd);
    drop(env);
    let mut variants = Vec::new();
    for (v, name) in names.iter().enumerate() {
        let rs = &runs[v];
        let num = |f: &dyn Fn(&Value) -> Option<f64>| median(rs.iter().filter_map(|r| f(&r["result"])).collect());
        let frame = |key: &str| -> f64 {
            median(
                rs.iter()
                    .flat_map(|r| r["result"]["frames"].as_array().cloned().unwrap_or_default())
                    .filter_map(|f| f["stats"][key].as_f64())
                    .collect(),
            )
        };
        variants.push(json!({
            "variant": name,
            "runs": rs.len(),
            "load_event_ms_median": num(&|r| r["load"].as_f64()),
            "dcl_ms_median": num(&|r| r["dcl"].as_f64()),
            "top_script_started_ms_median": num(&|r| r["stats"]["started"].as_f64()),
            "top_setup_ms_median": num(&|r| r["stats"]["setupMs"].as_f64()),
            "frame_setup_ms_median": frame("setupMs"),
            "frame_script_started_ms_median": frame("started"),
            "generic_rules_matched_top_median": num(&|r| r["stats"]["matched"].as_f64()),
            "last_run": rs.last().cloned(),
        }));
    }
    let csp_reports = kit.fx.since(csp_mark).iter().filter(|r| r.route() == "/csp-report").count();
    kit.px.stop();
    json!({
        "spike": "M6 cosmetic script cost and correctness",
        "rules": serde_json::to_value(&rules.stats).unwrap_or(Value::Null),
        "rule_build_ms": build_ms,
        "script_bytes": { "one_script": observe.len(), "split_every_document": split.len(), "split_site": site.len(), "all": all.len() },
        "targets": { "generic_class": ad_class, "generic_id": ad_id, "specific_host": specific_host, "specific_class": specific_sel },
        "variants": variants,
        "csp_reports": csp_reports,
    })
}
