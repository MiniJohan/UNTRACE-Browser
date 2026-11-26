//! `untrace --self-check <out.json>`: start the real application in its own data folder, verify
//! the M1 security boundaries end to end, write a report and exit (0 = all passed).
//! No network access: the probe page is served from a local folder mapped to a `.invalid` host.
//!
//! Checks:
//! 1. Content views carry no Tauri globals (`__TAURI_INTERNALS__`, `__TAURI__`, `ipc`).
//! 2. Hardening is in effect, read back from the engine (no host bridge, no password saving or
//!    autofill, SmartScreen off, local crash reports, history cleared).
//! 3. The developer-tools setting reads back as configured (off).
//! 4. The UI view refuses to navigate away from the app origin.
//! 5. The content view is visible where the UI reserved space (pixel check), and the UI's top
//!    bar is not covered.
//!
//! Milestone 2 (browser security baseline):
//! 6. HTTPS-only upgrades http:// and shows UNTRACE's panel when no secure version exists.
//! 7. Links to local files are blocked.
//! 8. Abused application-link types (ms-settings:) are refused without asking.
//! 9. Location is asked about, and "Block" reaches the page as a denial.
//! 10. A program download is held behind a question that flags it.
//! 11. "Remember for this site" is saved in the profile, listed, and Reset removes it.
//! 12. An accepted download is saved, completes and carries Mark-of-the-Web (ZoneId=3).
//! 13. A self-signed certificate is refused and explained (needs the HTTPS fixture that
//!     scripts/check.ps1 starts; reported as skipped, not passed, without it).
//!
//! Milestone 3 (network filtering), using each list's canary host (`*.canary.untrace.invalid`,
//! never resolvable): a blocked request gets UNTRACE's answer, an allowed one fails to resolve.
//! 14. Every enabled list is loaded and proves itself with its canary.
//! 15. The page's requests to listed hosts are blocked and counted; others are not touched.
//! 16. Requests from a shared worker are blocked too (worker requests reach one tab).
//! 17. A malware site is replaced by the warning; "Continue anyway" lets it through this session.
//! 18. A phishing site is replaced by the warning, naming its list.
//! 19. Turning a list off in Settings stops it blocking, verified; turning it on restores it.
//! 20. Turning blocking off for a site stops ads/trackers blocking there, but not the malware list.
//!
//! Milestone 4 (privacy controls):
//! 21. Tracking prevention reads back as configured (Balanced); Strict is applied and verified,
//!     then Balanced again.
//! 22. Tracking parameters are removed before the request leaves: the page's own address is
//!     clean and the tab counts them; switched off, they stay.
//! 23. A temporary tab keeps cookies and storage apart from normal tabs, and after it closes
//!     nothing it stored is on disk (positive control: the same data from a normal tab is).
//! 24. A site's cookies and storage are listed, deleted, and read back as gone.
//! 25. "Delete all" of cookies and site data leaves no cookie (read back).

use std::{
    path::PathBuf,
    sync::{Arc, Mutex, atomic::Ordering},
    thread,
    time::Duration,
};

use serde::Serialize;
use serde_json::{Value as Json, json};
use tauri::{AppHandle, Manager};
use untrace_core::{
    audit::AuditEvent,
    policy::Permission,
    registry::{Applier, Observed, Value},
};
use untrace_filter::{ListId, catalog::BLOCK_ADS_ID};
use untrace_webview::{ClearKinds, DEVTOOLS_ID, STRIP_PARAMS_ID, TRACKING_PREVENTION_ID};
use windows::Win32::{
    Foundation::{COLORREF, HWND, RECT},
    Graphics::Gdi::*,
    Storage::Xps::{PRINT_WINDOW_FLAGS, PrintWindow},
    UI::WindowsAndMessaging::GetClientRect,
};

use crate::{AppState, UI_NAV_BLOCKED, commands, filters::Applied, host};

/// Shared worker for check 16 (served from the probe folder).
const WORKER_JS: &str = "onconnect = async (e) => { const port = e.ports[0]; let r; \
try { await fetch('https://tracker.canary.untrace.invalid/from-worker', { mode: 'no-cors', cache: 'no-store' }); r = 'answered'; } \
catch (x) { r = 'failed'; } port.postMessage(r); };";

/// Fetch each canary from the page; blocked requests are answered, others fail to resolve.
const CANARY_PROBE_JS: &str = "window.__m3 = 'pending'; (async () => { \
const probe = async (u) => { try { await fetch(u, { mode: 'no-cors', cache: 'no-store' }); return 'answered'; } catch (e) { return 'failed'; } }; \
const r = { ads: await probe('https://ads.canary.untrace.invalid/ad.js'), \
tracker: await probe('https://tracker.canary.untrace.invalid/t.gif'), \
malware: await probe('https://malware.canary.untrace.invalid/payload.bin'), \
phishing: await probe('https://phishing.canary.untrace.invalid/kit.js'), \
control: await probe('https://unlisted.canary.untrace.invalid/x.js') }; \
window.__m3 = JSON.stringify(r); })(); 'started'";

/// Stores a marker (from `?m=`) as a cookie, in local storage and in IndexedDB.
const STORE_HTML: &str = "<!doctype html><html><head><meta charset=utf-8><title>store</title></head><body><script>\
const m = new URLSearchParams(location.search).get('m'); \
document.cookie = 'untrace_m4=' + m + '; max-age=3600; path=/'; localStorage.setItem('untrace_m4', m); \
const r = indexedDB.open('untrace_m4', 1); r.onupgradeneeded = () => r.result.createObjectStore('s'); \
r.onsuccess = () => { const t = r.result.transaction('s', 'readwrite'); t.objectStore('s').put(m, 'k'); \
t.oncomplete = () => { window.__stored = 'ok'; }; };</script></body></html>";
const SEEN_JS: &str = "JSON.stringify({ cookie: document.cookie, local: localStorage.getItem('untrace_m4') })";
const PROBE_HOST: &str = "selfcheck.untrace.invalid";
const PROBE_HTML: &str = "<!doctype html><html><head><meta charset=utf-8><title>UNTRACE self-check</title></head>\
<body style=\"margin:0;height:100vh;background:#00a000\"></body></html>";
const PROBE_JS: &str = "({ tauriInternals: typeof window.__TAURI_INTERNALS__, tauri: typeof window.__TAURI__, \
ipc: typeof window.ipc, origin: location.origin, title: document.title })";

#[derive(Serialize, Clone)]
struct Item {
    name: String,
    ok: bool,
    /// Not run (missing test fixture); reported, and does not count as a pass.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    skipped: bool,
    detail: Json,
}

type Results = Arc<Mutex<Vec<Item>>>;

fn push(r: &Results, name: &str, ok: bool, detail: Json) {
    r.lock().unwrap().push(Item {
        name: name.into(),
        ok,
        skipped: false,
        detail,
    });
}

fn push_skipped(r: &Results, name: &str, why: &str) {
    r.lock().unwrap().push(Item {
        name: name.into(),
        ok: true,
        skipped: true,
        detail: json!(why),
    });
}

fn on_main(app: &AppHandle, f: impl FnOnce() + Send + 'static) {
    let _ = app.run_on_main_thread(f);
}

fn sleep(ms: u64) {
    thread::sleep(Duration::from_millis(ms));
}

pub fn start(app: AppHandle, out: PathBuf) {
    thread::spawn(move || run(app, out));
}

fn run(app: AppHandle, out: PathBuf) {
    let results: Results = Arc::new(Mutex::new(Vec::new()));
    let ready = Arc::new(Mutex::new(false));

    // Wait for the engine, the first tab and the UI's layout report.
    for _ in 0..60 {
        let (a, r) = (app.clone(), ready.clone());
        on_main(&app, move || {
            let tab_ready = host()
                .map(|h| h.snapshot().tabs.first().map(|t| t.ready).unwrap_or(false))
                .unwrap_or(false);
            let laid_out = a.state::<AppState>().content_dip.lock().unwrap().is_some();
            *r.lock().unwrap() = tab_ready && laid_out;
        });
        sleep(250);
        if *ready.lock().unwrap() {
            break;
        }
    }
    if !*ready.lock().unwrap() {
        push(&results, "engine and UI ready", false, json!("timed out after 15 s"));
        finish(&app, &out, &results);
        return;
    }
    push(&results, "engine and UI ready", true, json!(null));

    // Serve the probe page and open it.
    let folder = app.state::<AppState>().layout.root.join("self-check-pages");
    let _ = std::fs::create_dir_all(&folder);
    let _ = std::fs::write(folder.join("probe.html"), PROBE_HTML);
    let _ = std::fs::write(folder.join("worker.js"), WORKER_JS);
    let r = results.clone();
    on_main(&app, move || {
        let Some(h) = host() else { return };
        let Some(id) = h.active_id() else { return };
        match h.map_folder(id, PROBE_HOST, &folder) {
            Ok(()) => h.navigate_active(&format!("https://{PROBE_HOST}/probe.html")),
            Err(e) => push(&r, "probe page served locally", false, json!(e)),
        }
    });
    sleep(2500);

    // 1. Globals visible to content.
    let r = results.clone();
    on_main(&app, move || {
        let Some(h) = host() else { return };
        let Some(id) = h.active_id() else { return };
        h.execute(id, PROBE_JS, move |json| {
            let v: Json = serde_json::from_str(&json).unwrap_or(Json::String(json));
            let ok = v["tauriInternals"] == "undefined"
                && v["tauri"] == "undefined"
                && v["ipc"] == "undefined"
                && v["origin"] == format!("https://{PROBE_HOST}");
            push(&r, "content views carry no Tauri globals", ok, v);
        });
    });
    sleep(800);

    // 2 + 3. Hardening and the developer-tools setting, read back from the engine.
    let (r, a) = (results.clone(), app.clone());
    on_main(&app, move || {
        let state = a.state::<AppState>();
        let info = host().map(|h| h.engine_info());
        for c in commands::checks(
            info.as_ref(),
            &state.config_status,
            state.engine_scrub.lock().unwrap().as_ref(),
        ) {
            push(
                &r,
                c.name,
                c.ok == Some(true),
                json!({ "ok": c.ok, "detail": c.detail }),
            );
        }
        let observed = host().map(|h| h.observe(DEVTOOLS_ID));
        let ok = observed == Some(Observed::Verified(Value::Bool(false)));
        push(
            &r,
            "developer tools read back as off",
            ok,
            json!(format!("{observed:?}")),
        );
    });
    sleep(500);

    // 4. UI navigation lock (target is unroutable, so even a failure would not reach the network).
    let before = UI_NAV_BLOCKED.load(Ordering::SeqCst);
    let a = app.clone();
    on_main(&app, move || {
        if let Some(w) = a.get_webview_window("main") {
            let _ = w.eval("location.href = 'https://ui-lock.untrace.invalid/'");
        }
    });
    sleep(1500);
    let (r, a) = (results.clone(), app.clone());
    on_main(&app, move || {
        let after = UI_NAV_BLOCKED.load(Ordering::SeqCst);
        let url = a
            .get_webview_window("main")
            .and_then(|w| w.url().ok())
            .map(|u| u.to_string())
            .unwrap_or_default();
        let ok = after > before && url.contains("tauri.localhost");
        push(
            &r,
            "UI view cannot navigate away",
            ok,
            json!({ "blocked_attempts": after - before, "ui_url": url }),
        );
    });
    sleep(500);

    // 5. Layout: content visible below the UI's top bar, top bar not covered.
    let (r, a) = (results.clone(), app.clone());
    on_main(&app, move || {
        let state = a.state::<AppState>();
        let Some(rect) = *state.content_dip.lock().unwrap() else {
            return;
        };
        let Some(w) = a.get_webview_window("main") else { return };
        let Ok(hwnd) = w.hwnd() else { return };
        let s = w.scale_factor().unwrap_or(1.0);
        let cx = ((rect.x + rect.w / 2.0) * s) as i32;
        let cy = ((rect.y + rect.h / 2.0) * s) as i32;
        let bar_y = ((rect.y / 2.0) * s).max(1.0) as i32;
        let (content, bar) = sample(hwnd, &[(cx, cy), (cx, bar_y)])
            .map(|v| (v[0].clone(), v[1].clone()))
            .unwrap_or_default();
        let ok = content == "#00a000" && bar != "#00a000" && !bar.is_empty();
        push(
            &r,
            "content view visible in its area, UI not covered",
            ok,
            json!({ "content_pixel": content, "top_bar_pixel": bar, "rect_dip": [rect.x, rect.y, rect.w, rect.h] }),
        );
    });
    sleep(500);

    m2_checks(&app, &results);
    m3_checks(&app, &results);
    popup_checks(&app, &results);
    redirect_checks(&app, &results);
    scriptlet_checks(&app, &results);
    m4_checks(&app, &results);
    m5_checks(&app, &results);
    m6_checks(&app, &results);
    m7_checks(&app, &results);
    m8_checks(&app, &results);
    appearance_checks(&app, &results);
    update_checks(&app, &results);
    sleep_checks(&app, &results);
    finish(&app, &out, &results);
}

/// Which self-check items exercise each protection. M7 exit criterion: every protection has at
/// least one; a unit test keeps this in step with Settings. Read-backs alone do not count.
pub const COVERAGE: &[(&str, &[&str])] = &[
    (
        "filter.ublock",
        &[
            "every block list is loaded and verified",
            "ad pop-ups opened by a click are refused; other new windows open",
            "the lists' scriptlets run before the page's own scripts",
            "rules fused with ones the matching library cannot compile still match",
            "a page cannot send its tab to a blocked site; the user can open it",
        ],
    ),
    (
        "performance.sleeping_tabs",
        &["a background tab sleeps, and wakes when opened"],
    ),
    (
        "filter.block_ads",
        &[
            "ad pop-ups opened by a click are refused; other new windows open",
            "a page cannot send its tab to a blocked site; the user can open it",
            "every block list is loaded and verified",
            "requests to listed hosts are blocked and counted, others untouched",
            "switching a list off stops it, verified; switching it on restores it",
            "a site exception stops ad/tracker blocking there, not malware/phishing blocking",
        ],
    ),
    (
        "filter.block_trackers",
        &[
            "every block list is loaded and verified",
            "requests to listed hosts are blocked and counted, others untouched",
            "requests from workers are blocked too",
            "a site exception stops ad/tracker blocking there, not malware/phishing blocking",
        ],
    ),
    (
        "filter.hide_elements",
        &[
            "the space blocked ads leave is hidden, in strict-CSP pages and cross-origin frames",
            "hiding follows its switch and the per-site switch",
        ],
    ),
    (
        "filter.auto_update",
        &["block lists are only updated while their switch is on"],
    ),
    (
        "filter.warn_malware",
        &[
            "requests to listed hosts are blocked and counted, others untouched",
            "malware sites are replaced by a warning; continuing lasts the session",
        ],
    ),
    (
        "filter.warn_phishing",
        &[
            "requests to listed hosts are blocked and counted, others untouched",
            "phishing sites are replaced by a warning naming the list",
            "the network layer blocks malware hosts the page check cannot see (WebSocket)",
        ],
    ),
    (
        "security.https_only",
        &[
            "HTTPS-only upgrades http:// and explains failures",
            "navigations UNTRACE cancels send nothing (HTTPS-only upgrade)",
        ],
    ),
    (
        "security.local_network",
        &[
            "parts of public sites cannot reach this computer unless the site is allowed",
            "public names that point into this computer are refused (DNS rebinding)",
        ],
    ),
    (
        "privacy.tracking_prevention",
        &["tracking prevention reads back as configured; changes are verified"],
    ),
    (
        "privacy.strip_tracking_params",
        &["tracking parameters are removed before the request leaves"],
    ),
    (
        "privacy.clear_cache_on_exit",
        &["closing UNTRACE deletes what its switches say, checked"],
    ),
    (
        "privacy.clear_site_data_on_exit",
        &["closing UNTRACE deletes what its switches say, checked"],
    ),
    (
        "network.encrypted_dns",
        &[
            "the engine's requests reach the network layer with this launch's credentials",
            "the network layer refuses anyone without this launch's credentials",
            "with the network layer stopped, nothing loads and nothing goes direct",
        ],
    ),
    (
        "network.webrtc_in_network_layer",
        &["WebRTC stays inside the network layer"],
    ),
    (
        "network.doh_provider",
        &["the Strict provider reads back as not in use outside Strict mode"],
    ),
    (
        "app.check_updates",
        &["UNTRACE updates are installed only with a valid signature for their version"],
    ),
    ("browser.devtools", &["developer tools read back as off"]),
];

/// Per protection: "passed", "failed", "partly" (some of its checks were not run) or
/// "not_run", with the names of failed checks.
pub fn coverage_result(checks: &[(String, bool, bool)]) -> Vec<Json> {
    COVERAGE
        .iter()
        .map(|(id, names)| {
            let found: Vec<&(String, bool, bool)> =
                names.iter().filter_map(|n| checks.iter().find(|c| c.0 == *n)).collect();
            let failed: Vec<&str> = found.iter().filter(|c| !c.1).map(|c| c.0.as_str()).collect();
            let run = found.iter().filter(|c| !c.2).count();
            let state = if !failed.is_empty() {
                "failed"
            } else if run == 0 {
                "not_run"
            } else if run < names.len() {
                "partly"
            } else {
                "passed"
            };
            json!({ "id": id, "state": state, "failed": failed, "checks": names })
        })
        .collect()
}

/// M8 test page: WebRTC with a STUN server on this computer's LAN address (the stand-in counts
/// what arrives). With the policy in effect nothing may arrive.
const RTC_HTML: &str = "<!doctype html><html><head><meta charset=utf-8><title>rtc</title>\
<script src=\"rtc.js\"></script></head><body>rtc</body></html>";
const RTC_JS: &str = "window.__rtc = 'pending'; (async () => { try { \
const p = new URLSearchParams(location.search); \
const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:' + p.get('lan') + ':' + p.get('port') }] }); \
pc.createDataChannel('probe'); let n = 0; pc.onicecandidate = (e) => { if (e.candidate && e.candidate.candidate) n++; }; \
await pc.setLocalDescription(await pc.createOffer()); await new Promise((r) => setTimeout(r, 3000)); \
window.__rtc = JSON.stringify({ api: typeof RTCPeerConnection, gathering: pc.iceGatheringState, candidates: n }); pc.close(); \
} catch (e) { window.__rtc = JSON.stringify({ error: e.name }); } })();";

/// This computer's LAN address, found without sending anything.
fn lan_ip() -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// A UDP stand-in for a STUN server: counts the datagrams it receives.
fn udp_stand_in(ip: std::net::IpAddr) -> Option<(u16, Arc<std::sync::atomic::AtomicUsize>)> {
    let s = std::net::UdpSocket::bind((ip, 0)).ok()?;
    let port = s.local_addr().ok()?.port();
    let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let n2 = n.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while s.recv_from(&mut buf).is_ok() {
            n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    Some((port, n))
}

/// M9 test material (D-016): a throw-away Ed25519 key pair made for this check only (its private
/// half was deleted), and signatures of `UPDATE_PAYLOAD` made with `cargo tauri signer sign
/// --app-version`: for 99.0.0, for 98.0.0, and for 99.0.0 with a second, foreign key.
const UPDATE_TEST_PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEQ3QTgxNjE5RDg0OEIxNjYKUldSbXNVallHUmFvMTc4QzU0VU80TlkvZ3BONTFtakxON2tOVEhnS1psMEpKQzVIOVhERmJaRVUK";
const UPDATE_PAYLOAD: &[u8] = b"UNTRACE self-check update payload\n";
const UPDATE_SIG_99: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVSbXNVallHUmFvMTBlenpFUVUxTm9YYnFNMm9qYi9SeEFnUHJoRzdCMkdIR3ZvM2kvTmFFeUZOd00rR3daNk16Zk9kMElyQm9MNC9zV09heStQemxIL2ZmRVE2UDJiSkFvPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzk1NjEzNzYwCWZpbGU6cGF5bG9hZC5iaW4JdmVyc2lvbjo5OS4wLjAKTEMzbHdhM3JwYjdkUHdwcVRSc21PL0JDa2hIaTNXSUZuNy8rRFUwdjBSZ1RBdkY2S0xaOStVV1VXTzA0ekZlVXoyMXdUV2hyUlVBaHY1MzExd0pRQ0E9PQo=";
const UPDATE_SIG_98: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVSbXNVallHUmFvMTZROWVOTWdWOUpJNlRhQlcxM21oV0pMRFRycXk5UHpQMmVTb29SL3htZXVqRzRNSXJSelYwNmN4WnRDbVNvaUpRVmhCWnhWcWVQd0dXZG9nV0MrdVFRPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzk1NjEzNzYwCWZpbGU6cGF5bG9hZDk4LmJpbgl2ZXJzaW9uOjk4LjAuMApXL2tvMXc2cmR3dFI1azNSc2I5L3ZtK05TWm1nTEZORUR3Q0RxQml5WXNyZVl1ZGE3bXRRdzFvbEdoR0cyc0Nvb3lVMVpUYnBtcHBGTmJzWlNob0NCUT09Cg==";
const UPDATE_SIG_FOREIGN: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVTWTlTd05WelZGTjJQRGVTQ2hwR2JmL2JNQzhJd3lQV3U4eDFLT0FuUjlqaU5CTlpBTHp2SEx2WDBnVWJoVGU0T2xtTVhLdTFQQjJ4SnI3VjZybXkyVHZRTXM1a3YvcndBPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzk1NjEzNzYwCWZpbGU6cGF5bG9hZEYuYmluCXZlcnNpb246OTkuMC4wCmpuckEwZlJ0ai84dndHMHNjSEdhenlHVXhuNE1KVWNjV0VQNVhHQzNIbVpZSU1aNGpIc1Vtb0V0OUtjQnYxN0hEcWhJalJzQVdvbDBVcXlTaEdtUURBPT0K";

/// M9 (D-016): UNTRACE's own updates. The switch stops the daily check, and the updater's own
/// verification (the same one that runs before an installer is started) accepts only an update
/// signed by the trusted key for exactly the version it announces. Offline: the manifest is
/// handed to the updater directly, nothing is requested.
fn update_checks(app: &AppHandle, results: &Results) {
    use tauri_plugin_updater::UpdaterExt;
    let state = app.state::<AppState>();
    let before = state.app_updates.attempts();
    let off = set_protection(app, crate::appupdate::AUTO_CHECK_ID, false);
    let attempted = crate::appupdate::tick(app);
    let after = state.app_updates.attempts();
    let on = set_protection(app, crate::appupdate::AUTO_CHECK_ID, true);
    let manifest = |sig: &str| {
        json!({
            "version": "99.0.0",
            "notes": "self-check",
            "pub_date": "2026-11-25T00:00:00Z",
            "platforms": { "windows-x86_64": {
                "signature": sig,
                "url": "https://updates.untrace.invalid/UNTRACE_99.0.0_x64-setup.exe"
            } }
        })
    };
    let updater = "https://updates.untrace.invalid/latest.json"
        .parse()
        .map_err(|e| format!("{e:?}"))
        .and_then(|u| app.updater_builder().endpoints(vec![u]).map_err(|e| e.to_string()))
        .and_then(|b| b.pubkey(UPDATE_TEST_PUBKEY).build().map_err(|e| e.to_string()));
    let verify = |sig: &str, bytes: &[u8]| -> String {
        match &updater {
            Err(e) => format!("no updater: {e}"),
            Ok(u) => match u.restore_update(manifest(sig)) {
                Ok(Some(update)) => match update.verify(bytes) {
                    Ok(()) => "accepted".into(),
                    Err(e) => format!("refused: {e}"),
                },
                Ok(None) => "not offered".into(),
                Err(e) => format!("no update: {e}"),
            },
        }
    };
    let mut tampered = UPDATE_PAYLOAD.to_vec();
    tampered[0] ^= 0x20;
    let good = verify(UPDATE_SIG_99, UPDATE_PAYLOAD);
    let changed = verify(UPDATE_SIG_99, &tampered);
    let foreign = verify(UPDATE_SIG_FOREIGN, UPDATE_PAYLOAD);
    let other_version = verify(UPDATE_SIG_98, UPDATE_PAYLOAD);
    let switch_ok = off["outcome"] != "failed" && !attempted && after == before && on["outcome"] != "failed";
    push(
        results,
        "UNTRACE updates are installed only with a valid signature for their version",
        switch_ok
            && good == "accepted"
            && changed.starts_with("refused")
            && foreign.starts_with("refused")
            && other_version.starts_with("refused"),
        json!({ "switched_off": off, "check_attempted_while_off": attempted, "switched_on": on,
                "correctly_signed": good, "changed_by_one_bit": changed, "foreign_key": foreign,
                "signed_for_another_version": other_version }),
    );
}

/// D-053: with "Websites follow this theme" on, pages see UNTRACE's light/dark choice; off,
/// they follow Windows. Read back from the engine and asked of the page itself.
fn appearance_checks(app: &AppHandle, results: &Results) {
    use untrace_core::settings::Theme;
    let set = |theme: Theme, follow: bool| -> String {
        let a = app.clone();
        on_main_get(app, move || {
            let state = a.state::<AppState>();
            let saved = state.store.lock().unwrap().update(|s| {
                s.theme = theme;
                s.pages_follow_theme = follow;
            });
            match (saved, host()) {
                (Err(e), _) => format!("not saved: {e}"),
                (Ok(()), Some(h)) => crate::appearance::apply(&a, &h).err().unwrap_or_default(),
                (Ok(()), None) => "no engine".into(),
            }
        })
        .unwrap_or_else(|| "timed out".into())
    };
    let look = |label: &str| -> Json {
        navigate(app, format!("https://{PROBE_HOST}/probe.html"));
        json!({
            "case": label,
            "page_dark": page_eval(app, "matchMedia('(prefers-color-scheme: dark)').matches"),
            "page_light": page_eval(app, "matchMedia('(prefers-color-scheme: light)').matches"),
            "read_back": on_main_get(app, || host().map(|h| format!("{:?}", h.page_color_scheme()))).flatten(),
        })
    };
    let e1 = set(Theme::Dark, true);
    let dark = look("Dark, follow");
    let e2 = set(Theme::Light, true);
    let light = look("Light, follow");
    let e3 = set(Theme::Black, false);
    let off = look("Black, not following");
    let e4 = set(Theme::System, true);
    push(
        results,
        "websites follow UNTRACE's light/dark choice when asked, and Windows otherwise",
        [&e1, &e2, &e3, &e4].iter().all(|e| e.is_empty())
            && dark["page_dark"] == "true"
            && dark["page_light"] == "false"
            && dark["read_back"] == "Some(Ok(Dark))"
            && light["page_dark"] == "false"
            && light["page_light"] == "true"
            && light["read_back"] == "Some(Ok(Light))"
            && off["read_back"] == "Some(Ok(Auto))",
        json!({ "cases": [dark, light, off], "errors": [e1, e2, e3, e4] }),
    );
}

/// Ask the engine to put a tab to sleep now and wait for its answer.
fn sleep_result(app: &AppHandle, id: Option<u32>) -> Result<(), String> {
    let rx = on_main_get(app, move || {
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
        match (host(), id) {
            (Some(h), Some(id)) => h.sleep_tab(id, move |r| {
                let _ = tx.send(r);
            }),
            _ => {
                let _ = tx.send(Err("no tab".into()));
            }
        }
        rx
    });
    rx.and_then(|rx| rx.recv_timeout(Duration::from_secs(10)).ok())
        .unwrap_or_else(|| Err("timed out".into()))
}

/// D-056: a tab in view is never put to sleep; a background tab sleeps (the engine reports it
/// suspended and the interface shows it), and opening it wakes it with its scripts running again.
fn sleep_checks(app: &AppHandle, results: &Results) {
    navigate(app, format!("https://{PROBE_HOST}/probe.html"));
    let started = page_eval(
        app,
        "(window.__ticks = 0, setInterval(() => window.__ticks++, 50), 'ok')",
    );
    let a = on_main_get(app, || host().and_then(|h| h.active_id())).flatten();
    let in_view = sleep_result(app, a);
    let b = on_main_get(app, || host().map(|h| h.new_tab(None))).flatten();
    sleep(1500);
    let slept = sleep_result(app, a);
    let state = |app: &AppHandle| -> (Option<bool>, Option<bool>) {
        on_main_get(app, move || {
            let h = host()?;
            let id = a?;
            let shown = h.snapshot().tabs.iter().find(|t| t.id == id).map(|t| t.sleeping);
            Some((h.engine_suspended(id), shown))
        })
        .flatten()
        .unwrap_or((None, None))
    };
    let (engine_asleep, shown_asleep) = state(app);
    on_main(app, move || {
        if let (Some(h), Some(id)) = (host(), a) {
            h.activate(id);
        }
    });
    sleep(800);
    let (engine_awake, shown_awake) = state(app);
    let t1 = page_eval(app, "window.__ticks");
    sleep(600);
    let t2 = page_eval(app, "window.__ticks");
    let ticking = matches!((t1.parse::<u64>(), t2.parse::<u64>()), (Ok(x), Ok(y)) if y > x);
    on_main(app, move || {
        if let (Some(h), Some(id)) = (host(), b) {
            h.close_tab(id);
        }
    });
    sleep(500);
    push(
        results,
        "a background tab sleeps, and wakes when opened",
        started == "\"ok\""
            && in_view.is_err()
            && slept.is_ok()
            && engine_asleep == Some(true)
            && shown_asleep == Some(true)
            && engine_awake == Some(false)
            && shown_awake == Some(false)
            && ticking,
        json!({
            "in_view_refused": in_view.err(),
            "background_sleep": slept.err().unwrap_or_else(|| "ok".into()),
            "engine_suspended_asleep": engine_asleep,
            "shown_sleeping": shown_asleep,
            "engine_suspended_after_opening": engine_awake,
            "shown_sleeping_after_opening": shown_awake,
            "timer_ticks_after_waking": [t1, t2],
        }),
    );
}

/// Milestone 8: WebRTC stays inside the network layer (D-052), in a normal and a temporary tab.
fn m8_checks(app: &AppHandle, results: &Results) {
    use std::sync::atomic::Ordering;
    let name = "WebRTC stays inside the network layer";
    let Some(ip) = lan_ip() else {
        push_skipped(
            results,
            name,
            "this computer has no LAN address to stand in for another device",
        );
        return;
    };
    let Some((port, count)) = udp_stand_in(ip) else {
        push(results, name, false, json!("the UDP stand-in could not start"));
        return;
    };
    // The stand-in must be reachable, or "nothing arrived" would prove nothing.
    let reachable = std::net::UdpSocket::bind((ip, 0))
        .and_then(|s| s.send_to(b"untrace", (ip, port)))
        .is_ok();
    sleep(200);
    let sanity = count.swap(0, Ordering::SeqCst);

    let folder = app.state::<AppState>().layout.root.join("self-check-pages");
    let _ = std::fs::write(folder.join("rtc.html"), RTC_HTML);
    let _ = std::fs::write(folder.join("rtc.js"), RTC_JS);
    let url = format!("https://{PROBE_HOST}/rtc.html?lan={ip}&port={port}");
    let run_in_active = |label: &str| -> Json {
        navigate(app, url.clone());
        let page = page_result(app, "window.__rtc");
        sleep(500);
        json!({ "tab": label, "page": page, "datagrams_received": count.swap(0, Ordering::SeqCst) })
    };

    let std_run = run_in_active("normal");
    // The same in a temporary tab (its own InPrivate profile, set up when the session starts).
    let std_id = on_main_get(app, || host().and_then(|h| h.active_id())).flatten();
    let temp_id = on_main_get(app, || host().map(|h| h.new_temporary_tab(None))).flatten();
    let mut temp_ready = false;
    for _ in 0..40 {
        sleep(250);
        temp_ready = on_main_get(app, move || {
            host().and_then(|h| {
                h.snapshot()
                    .tabs
                    .into_iter()
                    .find(|t| Some(t.id) == temp_id)
                    .map(|t| t.ready)
            })
        })
        .flatten()
        .unwrap_or(false);
        if temp_ready {
            break;
        }
    }
    sleep(800);
    let f2 = folder.clone();
    let mapped = on_main_get(app, move || {
        host()
            .zip(temp_id)
            .map(|(h, id)| h.map_folder(id, PROBE_HOST, &f2).is_ok())
    })
    .flatten()
    .unwrap_or(false);
    let temp_run = run_in_active("temporary");
    on_main(app, move || {
        if let Some(h) = host() {
            if let Some(id) = temp_id {
                h.close_tab(id);
            }
            if let Some(id) = std_id {
                h.activate(id);
            }
        }
    });
    sleep(1000);
    let observed = on_main_get(app, || {
        host().map(|h| format!("{:?}", h.observe(untrace_webview::WEBRTC_ID)))
    })
    .flatten();
    let ran = |r: &Json| r["page"]["api"] == "function" && r["page"]["gathering"].is_string();
    push(
        results,
        name,
        reachable
            && sanity == 1
            && temp_ready
            && mapped
            && ran(&std_run)
            && ran(&temp_run)
            && std_run["datagrams_received"] == 0
            && temp_run["datagrams_received"] == 0
            && observed.as_deref() == Some("Verified(Bool(true))"),
        json!({ "stand_in": format!("{ip}:{port}"), "stand_in_reachable": reachable && sanity == 1,
                "normal_tab": std_run, "temporary_tab": temp_run, "read_back": observed }),
    );
}

/// Milestone 7: the last protections without an end-to-end test of their own.
fn m7_checks(app: &AppHandle, results: &Results) {
    let state = app.state::<AppState>();

    // 51. "Update block lists automatically": with the switch off, the updater does not even
    //     try. (Turning it on is read back; no update runs here, the self-check never goes
    //     online.)
    let before = state.filters.attempts();
    let off = set_protection(app, crate::filters::AUTO_UPDATE_ID, false);
    let attempted = crate::filters::updater_tick(app);
    let after = state.filters.attempts();
    let on = set_protection(app, crate::filters::AUTO_UPDATE_ID, true);
    push(
        results,
        "block lists are only updated while their switch is on",
        off["outcome"] == "verified" && !attempted && after == before && on["outcome"] == "verified",
        json!({ "switched_off": off, "update_attempted_while_off": attempted, "update_runs_before": before,
                "update_runs_after": after, "switched_on": on }),
    );

    // 52. Clearing on close, by the routine closing uses (run without closing): cache and site
    //     data deleted, no cookie left (read back), and the page's stored marker gone.
    navigate(app, format!("https://{PROBE_HOST}/store.html?m=EXITMARK52"));
    let stored = wait_stored(app);
    let had = cookies_of(&cookie_sites(app), "untrace.invalid");
    let (tx, rx) = std::sync::mpsc::channel();
    let started = on_main_get(app, move || {
        crate::privacy::exit_clear_run(
            crate::privacy::ExitKinds {
                cache: true,
                site_data: true,
            },
            move |result, left, detail| {
                let _ = tx.send((result, left, detail));
            },
        )
    })
    .unwrap_or(false);
    let outcome = rx.recv_timeout(Duration::from_secs(15)).ok();
    navigate(app, format!("https://{PROBE_HOST}/probe.html"));
    let seen = page_eval(app, SEEN_JS);
    push(
        results,
        "closing UNTRACE deletes what its switches say, checked",
        stored
            && had >= 1
            && started
            && outcome
                .as_ref()
                .is_some_and(|(r, left, _)| *r == "done" && *left == Some(0))
            && !seen.contains("EXITMARK52"),
        json!({ "marker_stored": stored, "cookies_before": had, "started": started,
                "result": outcome.map(|(r, left, d)| json!({ "result": r, "cookies_left": left, "detail": d })),
                "page_sees_afterwards": seen }),
    );

    // 53. The Strict provider outside Strict mode: saved, but honestly not claimed as in use.
    let running = state.network().running().to_string();
    let changed = set_protection_value(app, crate::network::DOH_PROVIDER_ID, Value::Choice("cloudflare".into()));
    let back = set_protection_value(app, crate::network::DOH_PROVIDER_ID, Value::Choice("quad9".into()));
    push(
        results,
        "the Strict provider reads back as not in use outside Strict mode",
        running != "strict"
            && changed["outcome"] == "unverified"
            && changed["reason"].as_str().is_some_and(|r| r.contains("Strict"))
            && back["outcome"] == "unverified",
        json!({ "encrypted_dns_running": running, "to_cloudflare": changed, "back_to_quad9": back }),
    );
}

/// M6 test pages: a strict CSP (no inline script or style), elements matched by each list's
/// canary rules (generic and site-specific), one matched by a real EasyList rule (`##.ad--banner`),
/// a control, and a cross-origin frame that reports its own element's state.
const COSMETIC_HTML: &str = "<!doctype html><html><head><meta charset=utf-8>\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self'; style-src 'self'; frame-src https://cframe.untrace.invalid\">\
<title>cosmetic</title><script src=\"cosmetic.js\"></script></head><body>\
<div id=\"generic\" class=\"untrace-canary-easylist\">generic</div>\
<div id=\"specific\" class=\"untrace-canary-specific\">specific</div>\
<div id=\"real\" class=\"ad--banner\">real rule</div>\
<div id=\"control\" class=\"content\">content</div>\
<iframe src=\"https://cframe.untrace.invalid/cosmetic-frame.html\"></iframe></body></html>";
const COSMETIC_JS: &str = "window.__frameHidden = 'pending'; addEventListener('message', (e) => { \
if (e.origin === 'https://cframe.untrace.invalid' && e.data && e.data.cosmetic) window.__frameHidden = JSON.stringify(e.data.cosmetic); });";
const COSMETIC_FRAME_HTML: &str = "<!doctype html><html><head><meta charset=utf-8>\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self'; style-src 'self'\">\
<script src=\"cosmetic-frame.js\"></script></head><body><div id=\"f\" class=\"untrace-canary-easylist\">frame</div></body></html>";
const COSMETIC_FRAME_JS: &str = "addEventListener('load', () => { const el = document.getElementById('f'); \
parent.postMessage({ cosmetic: getComputedStyle(el).display }, 'https://selfcheck.untrace.invalid'); });";
const COSMETIC_STATE_JS: &str = "JSON.stringify(Object.fromEntries(['generic', 'specific', 'real', 'control'].map((id) => \
[id, getComputedStyle(document.getElementById(id)).display])))";

/// Open the cosmetic test page and read what is hidden there and in its frame.
fn cosmetic_state(app: &AppHandle) -> Json {
    navigate(app, format!("https://{PROBE_HOST}/cosmetic.html"));
    let page: Json = serde_json::from_str::<String>(&page_eval(app, COSMETIC_STATE_JS))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Json::Null);
    let frame = page_result(app, "window.__frameHidden");
    json!({ "page": page, "frame": frame })
}

fn hidden_all(s: &Json) -> bool {
    let p = &s["page"];
    p["generic"] == "none"
        && p["specific"] == "none"
        && p["real"] == "none"
        && p["control"] != "none"
        && s["frame"] == "none"
}

fn shown_all(s: &Json) -> bool {
    let p = &s["page"];
    p["generic"] == "block"
        && p["specific"] == "block"
        && p["real"] == "block"
        && p["control"] == "block"
        && s["frame"] == "block"
}

/// Milestone 6: element hiding, end to end, offline.
fn m6_checks(app: &AppHandle, results: &Results) {
    let folder = app.state::<AppState>().layout.root.join("self-check-pages");
    let _ = std::fs::write(folder.join("cosmetic.html"), COSMETIC_HTML);
    let _ = std::fs::write(folder.join("cosmetic.js"), COSMETIC_JS);
    let _ = std::fs::write(folder.join("cosmetic-frame.html"), COSMETIC_FRAME_HTML);
    let _ = std::fs::write(folder.join("cosmetic-frame.js"), COSMETIC_FRAME_JS);
    let f2 = folder.clone();
    let mapped = on_main_get(app, move || {
        host().and_then(|h| h.active_id().map(|id| (h, id))).map(|(h, id)| {
            h.map_folder(id, PROBE_HOST, &f2).is_ok() && h.map_folder(id, "cframe.untrace.invalid", &f2).is_ok()
        })
    })
    .flatten()
    .unwrap_or(false);

    // 45. Hidden in a strict-CSP page and in a cross-origin frame, before any page script asks.
    let on = cosmetic_state(app);
    let observed = on_main_get(app, || {
        host().map(|h| format!("{:?}", h.observe(untrace_webview::HIDE_ELEMENTS_ID)))
    })
    .flatten();
    push(
        results,
        "the space blocked ads leave is hidden, in strict-CSP pages and cross-origin frames",
        mapped && hidden_all(&on) && observed.as_deref() == Some("Verified(Bool(true))"),
        json!({ "state": on, "read_back": observed }),
    );

    // 46. The switch and the per-site exception turn hiding off (after a reload); on again.
    let off = set_protection(app, untrace_webview::HIDE_ELEMENTS_ID, false);
    let when_off = cosmetic_state(app);
    let back_on = set_protection(app, untrace_webview::HIDE_ELEMENTS_ID, true);
    let again = cosmetic_state(app);
    on_main_get(app, || {
        if let Some(h) = host() {
            h.set_site_exceptions(["untrace.invalid".to_string()]);
        }
    });
    let excepted = cosmetic_state(app);
    let saved = app
        .state::<AppState>()
        .store
        .lock()
        .unwrap()
        .settings()
        .filter_exceptions
        .clone();
    on_main_get(app, move || {
        if let Some(h) = host() {
            h.set_site_exceptions(saved);
        }
    });
    let restored = cosmetic_state(app);
    push(
        results,
        "hiding follows its switch and the per-site switch",
        off["outcome"] == "verified"
            && shown_all(&when_off)
            && back_on["outcome"] == "verified"
            && hidden_all(&again)
            && shown_all(&excepted)
            && hidden_all(&restored),
        json!({ "switched_off": off, "when_off": when_off, "switched_on": back_on, "when_on": again,
                "site_exception": excepted, "exception_removed": restored }),
    );
}

/// Run a script built at run time in the active tab and return its JSON result.
fn page_eval_owned(app: &AppHandle, js: String) -> String {
    let rx = on_main_get(app, move || {
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        if let Some(h) = host()
            && let Some(id) = h.active_id()
        {
            h.execute(id, &js, move |j| {
                let _ = tx.send(j);
            });
        }
        rx
    });
    rx.and_then(|rx| rx.recv_timeout(Duration::from_secs(5)).ok())
        .unwrap_or_default()
}

/// A stand-in for a device on this computer: counts the connections it receives and answers
/// each with an empty 200.
fn local_device() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("local device");
    let port = l.local_addr().map(|a| a.port()).unwrap_or(0);
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = hits.clone();
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut c = c;
            let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 2048];
            let _ = c.read(&mut buf);
            let _ = c.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
            );
        }
    });
    (port, hits)
}

/// Fetch `url` from the active page (no-cors) and wait for it to settle.
fn page_fetch(app: &AppHandle, url: &str) -> String {
    let js = format!(
        "window.__m5 = 'pending'; fetch('{url}', {{ mode: 'no-cors', cache: 'no-store' }}).then(() => window.__m5 = '\"answered\"', () => window.__m5 = '\"failed\"'); 'started'"
    );
    page_eval_owned(app, js);
    let r = page_result(app, "window.__m5");
    r.as_str().unwrap_or("").to_string()
}

fn set_local_sites(app: &AppHandle, sites: Vec<String>) {
    on_main_get(app, move || {
        if let Some(h) = host() {
            h.set_local_sites(sites);
        }
    });
}

/// Milestone 5: the network layer and local-network protection, end to end, offline. The
/// proxy resolves nothing here: canary names are refused by name, and the self-check's own
/// test names are answered from a table (`set_test_hosts`, self-check only).
fn m5_checks(app: &AppHandle, results: &Results) {
    let state = app.state::<AppState>();
    let Some(proxy) = state.network().proxy() else {
        for name in [
            "the engine's requests reach the network layer with this launch's credentials",
            "the network layer refuses anyone without this launch's credentials",
            "the network layer blocks malware hosts the page check cannot see (WebSocket)",
            "public names that point into this computer are refused (DNS rebinding)",
            "with the network layer stopped, nothing loads and nothing goes direct",
        ] {
            push_skipped(
                results,
                name,
                "Encrypted DNS is off in this profile, so the network layer is not running.",
            );
        }
        m5_local_checks(app, results, None);
        return;
    };

    // 38. Start-up check: a request from the engine reached the proxy with credentials, and the
    //     engine was started pointing at it.
    let check = on_main_get(app, || host().map(|h| h.network_check())).flatten();
    let args = on_main_get(app, || host().map(|h| h.engine_info().browser_arguments))
        .flatten()
        .unwrap_or_default();
    let observed = on_main_get(app, {
        let a = app.clone();
        move || {
            let state = a.state::<AppState>();
            let check = host().map(|h| h.network_check());
            format!("{:?}", state.network().observe(crate::network::DNS_MODE_ID, check))
        }
    })
    .unwrap_or_default();
    push(
        results,
        "the engine's requests reach the network layer with this launch's credentials",
        matches!(check, Some(untrace_webview::NetworkCheck::Passed { .. }))
            && args == proxy.browser_arguments()
            && observed.starts_with("Some(Verified("),
        json!({ "check": format!("{check:?}"), "engine_arguments": args, "settings_read_back": observed,
                "background_hosts_refused": proxy.hosts().iter().filter(|h| h.authenticated == 0 && h.refused_unauthenticated > 0).map(|h| h.host.clone()).collect::<Vec<_>>() }),
    );

    // 39. Other local programs cannot use the proxy: no credentials, wrong credentials -> 407.
    let ask = |auth: &str| -> String {
        use std::io::{Read, Write};
        let Ok(mut c) = std::net::TcpStream::connect(("127.0.0.1", proxy.port())) else {
            return "no connection".into();
        };
        let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
        let _ =
            c.write_all(format!("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n{auth}\r\n").as_bytes());
        let mut buf = [0u8; 256];
        let n = c.read(&mut buf).unwrap_or(0);
        String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or("")
            .to_string()
    };
    let before = proxy.stats().connections;
    let none = ask("");
    let wrong = ask("Proxy-Authorization: Basic dW50cmFjZTp3cm9uZw==\r\n");
    push(
        results,
        "the network layer refuses anyone without this launch's credentials",
        none.starts_with("HTTP/1.1 407") && wrong.starts_with("HTTP/1.1 407") && proxy.stats().connections == before,
        json!({ "without": none, "wrong": wrong }),
    );

    // 40. Backstop (D-042): a WebSocket, which the page-level check never sees, to the phishing
    //     canary host is refused by the network layer. (Not the malware canary: check 29 chose
    //     "Continue anyway" for it, which the network layer honours for the session.)
    open_probe(app);
    let canary = untrace_filter::engine::canary_host(ListId::Phishing);
    // Control: a WebSocket to a test name must reach the network layer at all.
    let (ws_port, _ws_hits) = local_device();
    let control = "ws.selfcheck.invalid";
    proxy
        .resolver()
        .set_test_hosts([(control.to_string(), vec!["127.0.0.1".parse().expect("ip")])].into());
    // Real pages load over the network before they open a WebSocket, which gives the engine the
    // proxy's credentials for that page; the probe page is served locally, so it makes one
    // ordinary request first. (Without it, the engine does not answer the proxy's challenge for
    // a WebSocket: M5 finding, see TESTING.)
    let warm = page_fetch(app, "https://netcheck-websocket.untrace.invalid/");
    let before = proxy.record(canary).map(|r| r.blocked_threat).unwrap_or(0);
    let stats_before = proxy.stats();
    let opened = page_eval_owned(
        app,
        format!(
            "(() => {{ const r = []; for (const u of ['wss://{canary}/socket', 'wss://{control}:{ws_port}/socket']) {{ \
             try {{ new WebSocket(u); r.push('opened'); }} catch (e) {{ r.push(String(e)); }} }} return r; }})()"
        ),
    );
    let mut after = before;
    for _ in 0..50 {
        after = proxy.record(canary).map(|r| r.blocked_threat).unwrap_or(0);
        if after > before && proxy.record(control).is_some() {
            break;
        }
        sleep(200);
    }
    let control_rec = proxy.record(control);
    proxy.resolver().set_test_hosts(Default::default());
    let stats_after = proxy.stats();
    push(
        results,
        "the network layer blocks malware hosts the page check cannot see (WebSocket)",
        after > before,
        json!({ "host": canary, "refused_before": before, "refused_after": after, "script": opened, "first_request": warm,
                "canary_record": proxy.record(canary).map(|r| serde_json::to_value(r).unwrap_or(Json::Null)),
                "control_record": control_rec.map(|r| serde_json::to_value(r).unwrap_or(Json::Null)),
                "unauthenticated_delta": stats_after.refused_unauthenticated - stats_before.refused_unauthenticated,
                "malformed_delta": stats_after.malformed - stats_before.malformed }),
    );

    m5_local_checks(app, results, Some(&proxy));

    // 43. A navigation UNTRACE cancels sends nothing: the HTTPS-only upgrade of an http://
    //     address must not let the plain request leave (the engine sends the request of a
    //     cancelled navigation unless UNTRACE answers it). The upgraded https attempt reaching
    //     the network layer is the control that it watched this name at all.
    let (dport, _dhits) = local_device();
    let plain = "plain.selfcheck.invalid";
    proxy
        .resolver()
        .set_test_hosts([(plain.to_string(), vec!["127.0.0.1".parse().expect("ip")])].into());
    navigate(app, format!("http://{plain}:{dport}/leak?secret=1"));
    sleep(1500);
    let rec = proxy.record(plain);
    proxy.resolver().set_test_hosts(Default::default());
    push(
        results,
        "navigations UNTRACE cancels send nothing (HTTPS-only upgrade)",
        rec.as_ref().is_some_and(|r| r.plain_http == 0 && r.authenticated >= 1),
        json!({ "record": rec.map(|r| json!({ "plain_http": r.plain_http, "requests_with_credentials": r.authenticated,
                "connections": r.connections })) }),
    );

    // 44. Fail closed: with the proxy not answering, a request the page check allows neither
    //     loads nor goes to the device directly. (From the probe page again: check 43 left the
    //     tab on another site's error panel.)
    open_probe(app);
    let (port, hits) = local_device();
    set_local_sites(app, vec!["untrace.invalid".into()]);
    proxy.set_paused(true);
    let paused = page_fetch(app, &format!("http://127.0.0.1:{port}/direct"));
    proxy.set_paused(false);
    let direct_hits = hits.load(std::sync::atomic::Ordering::SeqCst);
    let resumed = page_fetch(app, &format!("http://127.0.0.1:{port}/after"));
    let resumed_hits = hits.load(std::sync::atomic::Ordering::SeqCst);
    restore_local_sites(app);
    push(
        results,
        "with the network layer stopped, nothing loads and nothing goes direct",
        paused == "failed" && direct_hits == 0 && resumed == "answered" && resumed_hits == 1,
        json!({ "while_stopped": paused, "device_reached_while_stopped": direct_hits,
                "after_restart": resumed, "device_reached_after": resumed_hits }),
    );
}

fn restore_local_sites(app: &AppHandle) {
    let saved = app
        .state::<AppState>()
        .store
        .lock()
        .unwrap()
        .settings()
        .local_network_sites
        .clone();
    set_local_sites(app, saved);
}

/// 41–42: local-network protection (D-040), from the probe page (a public site).
fn m5_local_checks(app: &AppHandle, results: &Results, proxy: Option<&untrace_net::Proxy>) {
    open_probe(app);
    let (port, hits) = local_device();
    // 41. A public page's request to this computer is blocked by UNTRACE, never reaching it;
    //     allowed for the site, it goes through.
    let blocked = page_fetch(app, &format!("http://127.0.0.1:{port}/literal"));
    let tab = on_main_get(app, active_tab).unwrap_or(Json::Null);
    let hits_blocked = hits.load(std::sync::atomic::Ordering::SeqCst);
    set_local_sites(app, vec!["untrace.invalid".into()]);
    let allowed = page_fetch(app, &format!("http://127.0.0.1:{port}/allowed"));
    let hits_allowed = hits.load(std::sync::atomic::Ordering::SeqCst);
    restore_local_sites(app);
    let observed = on_main_get(app, || {
        host().map(|h| format!("{:?}", h.observe(untrace_webview::LOCAL_NETWORK_ID)))
    })
    .flatten();
    push(
        results,
        "parts of public sites cannot reach this computer unless the site is allowed",
        hits_blocked == 0
            && tab["blocked"]["localNetwork"].as_u64() == Some(1)
            && tab["blocked"]["hosts"]
                .as_array()
                .is_some_and(|h| h.iter().any(|x| x["local"] == true))
            && hits_allowed == 1
            && allowed == "answered"
            && observed.as_deref() == Some("Verified(Bool(true))"),
        json!({ "blocked_fetch": blocked, "device_reached_when_blocked": hits_blocked, "counted": tab["blocked"]["localNetwork"],
                "allowed_fetch": allowed, "device_reached_when_allowed": hits_allowed, "read_back": observed }),
    );

    // 42. DNS rebinding (needs the network layer): a public name that resolves to this computer
    //     is refused, unless a page allowed to reach the local network asks for it.
    let Some(proxy) = proxy else {
        push_skipped(
            results,
            "public names that point into this computer are refused (DNS rebinding)",
            "Encrypted DNS is off.",
        );
        return;
    };
    let name = "rebind.selfcheck.invalid";
    proxy
        .resolver()
        .set_test_hosts([(name.to_string(), vec!["127.0.0.1".parse().expect("ip")])].into());
    // https: a plain-http name would be stopped earlier as mixed content. The stand-in device
    // speaks no TLS, so even when the proxy connects the fetch fails; the device's connection
    // count shows whether the proxy connected.
    let start = hits.load(std::sync::atomic::Ordering::SeqCst);
    let refused = page_fetch(app, &format!("https://{name}:{port}/rebind"));
    let rec = proxy.record(name);
    let hits_refused = hits.load(std::sync::atomic::Ordering::SeqCst) - start;
    set_local_sites(app, vec!["untrace.invalid".into()]);
    let announced = page_fetch(app, &format!("https://{name}:{port}/announced"));
    let hits_announced = hits.load(std::sync::atomic::Ordering::SeqCst) - start;
    restore_local_sites(app);
    proxy.resolver().set_test_hosts(Default::default());
    push(
        results,
        "public names that point into this computer are refused (DNS rebinding)",
        refused == "failed"
            && hits_refused == 0
            && rec.as_ref().is_some_and(|r| r.blocked_local == 1)
            && hits_announced >= 1,
        json!({ "refused_fetch": refused, "device_reached": hits_refused, "record": rec.map(|r| json!({ "blocked_local": r.blocked_local, "reason": r.last_error })),
                "allowed_site_fetch": announced, "device_reached_when_allowed": hits_announced }),
    );
}

/// Run a script in the active tab and return its JSON result.
fn page_eval(app: &AppHandle, js: &'static str) -> String {
    let rx = on_main_get(app, move || {
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        if let Some(h) = host()
            && let Some(id) = h.active_id()
        {
            h.execute(id, js, move |j| {
                let _ = tx.send(j);
            });
        }
        rx
    });
    rx.and_then(|rx| rx.recv_timeout(Duration::from_secs(5)).ok())
        .unwrap_or_default()
}

/// Wait until a page variable holding a JSON string is set, and parse it.
fn page_result(app: &AppHandle, var_js: &'static str) -> Json {
    for _ in 0..25 {
        let raw = page_eval(app, var_js);
        let s: String = serde_json::from_str(&raw).unwrap_or_default();
        if !s.is_empty() && s != "pending" {
            return serde_json::from_str(&s).unwrap_or(Json::String(s));
        }
        sleep(200);
    }
    Json::Null
}

fn open_probe(app: &AppHandle) {
    on_main(app, || {
        if let Some(h) = host() {
            h.navigate_active(&format!("https://{PROBE_HOST}/probe.html"));
        }
    });
    sleep(1500);
}

/// Change a protection exactly as Settings does (validate → apply → read back → save).
fn set_protection(app: &AppHandle, id: &'static str, on: bool) -> Json {
    set_protection_value(app, id, Value::Bool(on))
}

fn set_protection_value(app: &AppHandle, id: &'static str, value: Value) -> Json {
    let a = app.clone();
    on_main_get(app, move || {
        let state = a.state::<AppState>();
        let mut store = state.store.lock().unwrap();
        let mut applier = Applied {
            host: host(),
            filters: &state.filters,
            exit: &state.exit_clear,
            network: state.network(),
        };
        let outcome = state.registry.change(id, value, &mut store, &state.audit, &mut applier);
        serde_json::to_value(outcome).unwrap_or(Json::Null)
    })
    .unwrap_or(Json::Null)
}

/// Files under `dir` whose bytes contain `needle`, and how many files could not be read.
fn files_containing(dir: &std::path::Path, needle: &[u8], hits: &mut Vec<String>, unreadable: &mut usize) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            files_containing(&p, needle, hits, unreadable);
        } else {
            match std::fs::read(&p) {
                Ok(b) if b.windows(needle.len()).any(|w| w == needle) => hits.push(p.display().to_string()),
                Ok(_) => {}
                Err(_) => *unreadable += 1,
            }
        }
    }
}

fn navigate(app: &AppHandle, url: String) {
    on_main(app, move || {
        if let Some(h) = host() {
            h.navigate_active(&url);
        }
    });
    sleep(1500);
}

/// Wait until the page has stored its marker everywhere (`window.__stored`).
fn wait_stored(app: &AppHandle) -> bool {
    for _ in 0..25 {
        if page_eval(app, "window.__stored || ''") == "\"ok\"" {
            return true;
        }
        sleep(200);
    }
    false
}

fn cookie_sites(app: &AppHandle) -> Json {
    let rx = on_main_get(app, || {
        let (tx, rx) = std::sync::mpsc::channel();
        if let Some(h) = host() {
            h.cookie_sites(move |r| {
                let _ = tx.send(r);
            });
        }
        rx
    });
    match rx.and_then(|rx| rx.recv_timeout(Duration::from_secs(10)).ok()) {
        Some(Ok(sites)) => serde_json::to_value(sites).unwrap_or(Json::Null),
        Some(Err(e)) => json!({ "error": e }),
        None => json!({ "error": "no answer" }),
    }
}

fn cookies_of(sites: &Json, site: &str) -> u64 {
    sites
        .as_array()
        .and_then(|a| a.iter().find(|s| s["site"] == site))
        .and_then(|s| s["cookies"].as_u64())
        .unwrap_or(0)
}

/// Milestone 4: privacy controls, end to end, without network access.
fn m4_checks(app: &AppHandle, results: &Results) {
    let folder = app.state::<AppState>().layout.root.join("self-check-pages");
    let _ = std::fs::write(folder.join("store.html"), STORE_HTML);
    let data_dir = app.state::<AppState>().layout.content_webview.clone();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp_marker = format!("TEMPMARK{nonce}");
    let std_marker = format!("STDMARK{nonce}");

    // 21. Tracking prevention: read back, changed to Strict and back, each verified.
    let observe = |app: &AppHandle| {
        on_main_get(app, || {
            host().map(|h| format!("{:?}", h.observe(TRACKING_PREVENTION_ID)))
        })
        .flatten()
    };
    let initial = observe(app);
    let strict = set_protection_value(app, TRACKING_PREVENTION_ID, Value::Choice("strict".into()));
    let read_strict = observe(app);
    let balanced = set_protection_value(app, TRACKING_PREVENTION_ID, Value::Choice("balanced".into()));
    push(
        results,
        "tracking prevention reads back as configured; changes are verified",
        initial.as_deref() == Some("Verified(Choice(\"balanced\"))")
            && strict["outcome"] == "verified"
            && read_strict.as_deref() == Some("Verified(Choice(\"strict\"))")
            && balanced["outcome"] == "verified",
        json!({ "initial": initial, "to_strict": strict, "read_back": read_strict, "to_balanced": balanced }),
    );

    // 22. Tracking parameters removed before the request leaves; kept when switched off.
    //     The address is on a canary host that never resolves: the cleaning must happen before
    //     any lookup, and UNTRACE's error panel names the address the engine actually requested.
    //     (Pages served from a mapped local folder, like the probe page, bypass the request event,
    //     so they cannot show this; that result is recorded for information only.)
    let tracked = "https://params.canary.untrace.invalid/landing?utm_source=selfcheck&keep=1&fbclid=abc";
    navigate(app, tracked.into());
    let tab_on = on_main_get(app, active_tab).unwrap_or(Json::Null);
    let off = set_protection(app, STRIP_PARAMS_ID, false);
    navigate(app, tracked.into());
    let tab_off = on_main_get(app, active_tab).unwrap_or(Json::Null);
    let on = set_protection(app, STRIP_PARAMS_ID, true);
    navigate(
        app,
        format!("https://{PROBE_HOST}/probe.html?utm_source=selfcheck&keep=1"),
    );
    let mapped_page = page_eval(app, "location.search");
    let blocked = &tab_on["blocked"];
    push(
        results,
        "tracking parameters are removed before the request leaves",
        tab_on["interstitial"]["url"] == "https://params.canary.untrace.invalid/landing?keep=1"
            && blocked["params"].as_u64() == Some(2)
            && blocked["paramNames"] == json!(["utm_source", "fbclid"])
            && off["outcome"] == "verified"
            && tab_off["interstitial"]["url"] == tracked
            && on["outcome"] == "verified",
        json!({ "requested": tab_on["interstitial"]["url"], "counted": blocked["params"], "names": blocked["paramNames"],
                "switched_off": off, "requested_when_off": tab_off["interstitial"]["url"], "switched_on": on,
                "info_mapped_folder_page_saw": mapped_page }),
    );

    // 23. Temporary tab: isolated from normal tabs; nothing on disk after it closes.
    let std_id = on_main_get(app, || host().and_then(|h| h.active_id())).flatten();
    let temp_id = on_main_get(app, || host().map(|h| h.new_temporary_tab(None))).flatten();
    let mut temp_ready = false;
    for _ in 0..40 {
        sleep(250);
        let ready = on_main_get(app, move || {
            host().and_then(|h| {
                h.snapshot()
                    .tabs
                    .into_iter()
                    .find(|t| Some(t.id) == temp_id)
                    .map(|t| t.ready)
            })
        })
        .flatten()
        .unwrap_or(false);
        if ready {
            temp_ready = true;
            break;
        }
    }
    sleep(800);
    let f2 = folder.clone();
    let mapped = on_main_get(app, move || {
        host()
            .zip(temp_id)
            .map(|(h, id)| h.map_folder(id, PROBE_HOST, &f2).is_ok())
    })
    .flatten()
    .unwrap_or(false);
    navigate(app, format!("https://{PROBE_HOST}/store.html?m={temp_marker}"));
    let stored_temp = wait_stored(app);
    let temp_saw = page_eval(app, SEEN_JS);
    let temp_tab = on_main_get(app, active_tab).unwrap_or(Json::Null);
    let temp_level = on_main_get(app, || host().map(|h| h.engine_info().temp_tracking_prevention_level))
        .flatten()
        .flatten();
    // A normal tab must not see it.
    on_main(app, move || {
        if let (Some(h), Some(id)) = (host(), std_id) {
            h.activate(id);
        }
    });
    navigate(app, format!("https://{PROBE_HOST}/probe.html"));
    let std_saw = page_eval(app, SEEN_JS);
    // Positive control: the same data from the normal tab reaches the disk.
    navigate(app, format!("https://{PROBE_HOST}/store.html?m={std_marker}"));
    let stored_std = wait_stored(app);
    on_main(app, move || {
        if let (Some(h), Some(id)) = (host(), temp_id) {
            h.close_tab(id);
        }
    });
    let mut control = Vec::new();
    let mut unreadable = 0;
    for _ in 0..20 {
        sleep(1000);
        control.clear();
        unreadable = 0;
        files_containing(&data_dir, std_marker.as_bytes(), &mut control, &mut unreadable);
        if !control.is_empty() {
            break;
        }
    }
    sleep(3000);
    let mut residue = Vec::new();
    let mut unreadable_after = 0;
    files_containing(&data_dir, temp_marker.as_bytes(), &mut residue, &mut unreadable_after);
    let temp_gone = on_main_get(app, || host().map(|h| h.engine_info().temporary_tabs)).flatten() == Some(0);
    push(
        results,
        "temporary tabs are isolated and leave nothing on disk",
        temp_ready
            && mapped
            && stored_temp
            && temp_tab["temporary"] == true
            && temp_saw.contains(&temp_marker)
            && temp_level.as_deref() == Some("balanced")
            && !std_saw.contains(&temp_marker)
            && stored_std
            && !control.is_empty()
            && residue.is_empty()
            && temp_gone,
        json!({ "temporary_tab_saw": temp_saw, "normal_tab_saw": std_saw, "temp_tracking_level": temp_level,
                "files_with_temporary_marker_after_close": residue, "unreadable_files": unreadable_after,
                "positive_control_files": control, "positive_control_unreadable": unreadable }),
    );

    // 24. One site's cookies and storage: listed, deleted, read back as gone.
    let site = "untrace.invalid";
    let before = cookie_sites(app);
    let rx = on_main_get(app, move || {
        let (tx, rx) = std::sync::mpsc::channel();
        if let Some(h) = host() {
            h.delete_site_data(site, move |r| {
                let _ = tx.send(r);
            });
        }
        rx
    });
    let left = rx.and_then(|rx| rx.recv_timeout(Duration::from_secs(10)).ok());
    sleep(500);
    navigate(app, format!("https://{PROBE_HOST}/probe.html"));
    let saw_after = page_eval(app, SEEN_JS);
    push(
        results,
        "a site's cookies and storage are listed, deleted and read back as gone",
        cookies_of(&before, site) >= 1 && matches!(left, Some(Ok(0))) && !saw_after.contains(&std_marker),
        json!({ "listed": before, "cookies_left": format!("{left:?}"), "page_saw_after": saw_after }),
    );

    // 25. "Delete all" cookies and site data: no cookie left (read back).
    navigate(app, format!("https://{PROBE_HOST}/store.html?m={std_marker}"));
    let stored_again = wait_stored(app);
    let with_cookie = cookie_sites(app);
    let rx = on_main_get(app, || {
        let (tx, rx) = std::sync::mpsc::channel();
        let started = host().is_some_and(|h| {
            h.clear_data(
                ClearKinds {
                    site_data: true,
                    ..Default::default()
                },
                move |r| {
                    let _ = tx.send(r);
                },
            )
        });
        (started, rx)
    });
    let cleared = rx.and_then(|(started, rx)| started.then(|| rx.recv_timeout(Duration::from_secs(10)).ok()).flatten());
    let after = cookie_sites(app);
    push(
        results,
        "deleting all cookies and site data leaves none",
        stored_again
            && cookies_of(&with_cookie, site) >= 1
            && matches!(cleared, Some(Ok(())))
            && after.as_array().is_some_and(|a| a.is_empty()),
        json!({ "before": with_cookie, "cleared": format!("{cleared:?}"), "after": after }),
    );
}

/// Milestone 3: network filtering, end to end, without network access.
/// A left click in the active tab, as a person's: the engine treats it as a user gesture.
fn click_active(app: &AppHandle, x: f64, y: f64) -> bool {
    let send = move |kind: &'static str| {
        let rx = on_main_get(app, move || {
            let (tx, rx) = std::sync::mpsc::channel::<bool>();
            match host().and_then(|h| h.active_id().map(|id| (h, id))) {
                Some((h, id)) => h.devtools_call(
                    id,
                    "Input.dispatchMouseEvent",
                    &format!(r#"{{"type":"{kind}","x":{x},"y":{y},"button":"left","buttons":1,"clickCount":1}}"#),
                    move |r| {
                        let _ = tx.send(r.is_ok());
                    },
                ),
                None => {
                    let _ = tx.send(false);
                }
            }
            rx
        });
        rx.and_then(|rx| rx.recv_timeout(Duration::from_secs(5)).ok())
            .unwrap_or(false)
    };
    send("mousePressed") && send("mouseReleased")
}

/// D-057: the scriptlet canary (`set` on the self-check host) has run when the page's first
/// script runs, and the value is still there after the page has loaded.
fn scriptlet_checks(app: &AppHandle, results: &Results) {
    assert_eq!(PROBE_HOST, untrace_filter::scriptlets::SCRIPTLET_CANARY_HOST);
    let page = "<!doctype html><meta charset=utf-8><title>scriptlets</title>\
                <script>window.__early = window.untraceScriptletCanary === true;</script><body>scriptlets</body>";
    let folder = app.state::<AppState>().layout.root.join("self-check-pages");
    let _ = std::fs::write(folder.join("scriptlets.html"), page);
    navigate(app, format!("https://{PROBE_HOST}/scriptlets.html"));
    let seen = page_eval(
        app,
        "JSON.stringify({ early: window.__early === true, after: window.untraceScriptletCanary === true })",
    );
    // The engine returns the script's string result as a JSON string literal.
    let v: Json = serde_json::from_str::<String>(&seen)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Json::Null);
    push(
        results,
        "the lists' scriptlets run before the page's own scripts",
        v["early"] == true && v["after"] == true,
        json!({ "page_saw": v, "raw": seen, "scriptlets_from": untrace_filter::scriptlets::resources_version() }),
    );
}

/// 2026-11-26: the lists' pop-up rules (which the matching library drops) are applied by
/// UNTRACE. Each click on the test page opens one window: an ad pop-up (the pop-up canary),
/// a blank window sent to the canary a moment later (as pop-unders do), and an ordinary page.
fn popup_checks(app: &AppHandle, results: &Results) {
    let canary = untrace_filter::popup::POPUP_CANARY_HOST;
    let page = format!(
        "<!doctype html><meta charset=utf-8><title>pop-ups</title><body style='margin:0;height:100vh'>\
         <script>let n=0;addEventListener('click',()=>{{n++;\
         if(n===1)open('https://{canary}/ad','_blank');\
         if(n===2){{const w=open('about:blank','_blank');if(w)setTimeout(()=>{{try{{w.location.href='https://{canary}/under'}}catch(e){{}}}},300)}}\
         if(n===3)open('https://{PROBE_HOST}/probe.html?opened','_blank')}})</script>"
    );
    let folder = app.state::<AppState>().layout.root.join("self-check-pages");
    let _ = std::fs::write(folder.join("popups.html"), page);
    navigate(app, format!("https://{PROBE_HOST}/popups.html"));
    let main = on_main_get(app, || host().and_then(|h| h.active_id())).flatten();
    let popups = move || -> (Vec<u32>, u32) {
        on_main_get(app, move || {
            let snap = host()?.snapshot();
            let refused = snap
                .tabs
                .iter()
                .find(|t| Some(t.id) == main)
                .map(|t| t.blocked.popups)?;
            Some((snap.tabs.iter().map(|t| t.id).collect(), refused))
        })
        .flatten()
        .unwrap_or_default()
    };
    let mut steps = Vec::new();
    for _ in 0..3 {
        let (before, refused_before) = popups();
        let clicked = click_active(app, 200.0, 200.0);
        sleep(2500);
        let (after, refused_after) = popups();
        let opened: Vec<u32> = after.into_iter().filter(|id| !before.contains(id)).collect();
        steps.push(json!({ "clicked": clicked, "opened": opened.len(), "refused": refused_after.saturating_sub(refused_before) }));
        on_main(app, move || {
            if let Some(h) = host() {
                for id in opened {
                    h.close_tab(id);
                }
                if let Some(id) = main {
                    h.activate(id);
                }
            }
        });
        sleep(600);
    }
    let step = |i: usize, opened: u64, refused: u64| {
        steps[i]["clicked"] == true && steps[i]["opened"] == opened && steps[i]["refused"] == refused
    };
    push(
        results,
        "ad pop-ups opened by a click are refused; other new windows open",
        step(0, 0, 1) && step(1, 0, 1) && step(2, 1, 0),
        json!({ "ad_popup": steps[0], "blank_then_ad": steps[1], "ordinary_window": steps[2] }),
    );
}

/// D-058, found on 9anime.es: (1) a rule the matching library cannot compile no longer
/// disables the working rules it fuses them with (the regular-expression canary); (2) a page
/// cannot send its tab to a site the lists block as a page, while the user still can.
fn redirect_checks(app: &AppHandle, results: &Results) {
    open_probe(app);
    page_eval(
        app,
        "window.__rx = 'pending'; fetch('https://regex.canary.untrace.invalid/check.js', \
         { mode: 'no-cors', cache: 'no-store' }).then(() => { window.__rx = 'answered'; }, \
         () => { window.__rx = 'failed'; }); 'started'",
    );
    let seen = page_result(app, "window.__rx");
    push(
        results,
        "rules fused with ones the matching library cannot compile still match",
        seen == "answered",
        json!({ "page_saw": seen, "canary": untrace_filter::engine::regex_canary_url() }),
    );

    let target = untrace_filter::engine::DOCUMENT_CANARY_HOST;
    let page = format!(
        "<!doctype html><meta charset=utf-8><title>redirect</title><body style='margin:0;height:100vh'>\
         <script>addEventListener('click',()=>{{location.href='https://{target}/landing'}})</script>"
    );
    let folder = app.state::<AppState>().layout.root.join("self-check-pages");
    let _ = std::fs::write(folder.join("redirect.html"), page);
    let start = format!("https://{PROBE_HOST}/redirect.html");
    navigate(app, start.clone());
    let clicked = click_active(app, 200.0, 200.0);
    sleep(2000);
    let after_click = on_main_get(app, active_tab).unwrap_or(Json::Null);
    // The same address, opened by the user: not stopped (it then fails to load: `.invalid`).
    navigate(app, format!("https://{target}/typed"));
    sleep(1500);
    let typed = on_main_get(app, active_tab).unwrap_or(Json::Null);
    let stayed = after_click["url"] == start.as_str()
        && after_click["blocked"]["navigations"] == 1
        && after_click["notice"].as_str().is_some_and(|n| n.contains(target));
    let user_went = typed["interstitial"]["kind"] == "load_error"
        && typed["interstitial"]["host"] == target
        && typed["blocked"]["navigations"] == 0;
    push(
        results,
        "a page cannot send its tab to a blocked site; the user can open it",
        clicked && stayed && user_went,
        json!({ "clicked": clicked, "after_click": { "url": after_click["url"], "blocked": after_click["blocked"],
                "notice": after_click["notice"] }, "typed": { "url": typed["url"], "interstitial": typed["interstitial"] } }),
    );
}

fn m3_checks(app: &AppHandle, results: &Results) {
    // 14. Lists loaded and verified by their canaries.
    let states = on_main_get(app, || {
        let h = host();
        ListId::ALL
            .iter()
            .map(|id| {
                let o = h
                    .as_ref()
                    .map(|h| h.filter_state(*id))
                    .unwrap_or(Observed::Unverifiable("no engine".into()));
                (format!("{id:?}"), o == Observed::Verified(Value::Bool(true)))
            })
            .collect::<Vec<_>>()
    })
    .unwrap_or_default();
    push(
        results,
        "every block list is loaded and verified",
        states.len() == ListId::ALL.len() && states.iter().all(|(_, ok)| *ok),
        json!(states),
    );

    // 15. Requests from the page: listed hosts blocked and counted, others untouched.
    open_probe(app);
    page_eval(app, CANARY_PROBE_JS);
    let seen = page_result(app, "window.__m3");
    let tab = on_main_get(app, active_tab).unwrap_or(Json::Null);
    let blocked = &tab["blocked"];
    let hosts: Vec<String> = blocked["hosts"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|h| h["host"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let ok = seen["ads"] == "answered"
        && seen["tracker"] == "answered"
        && seen["malware"] == "answered"
        && seen["phishing"] == "answered"
        && seen["control"] == "failed"
        && blocked["requests"].as_u64() == Some(2)
        && blocked["threats"].as_u64() == Some(2)
        && hosts.iter().any(|h| h == "ads.canary.untrace.invalid")
        && !hosts.iter().any(|h| h.starts_with("unlisted."));
    push(
        results,
        "requests to listed hosts are blocked and counted, others untouched",
        ok,
        json!({ "page_saw": seen, "blocked": blocked }),
    );

    // 16. A shared worker's request is blocked (worker requests reach exactly one tab).
    let before = on_main_get(app, || host().map(|h| h.engine_info().worker_requests_blocked)).flatten();
    page_eval(
        app,
        "window.__w = 'pending'; try { const w = new SharedWorker('worker.js'); \
         w.port.onmessage = (e) => { window.__w = JSON.stringify(e.data); }; w.port.start(); } \
         catch (e) { window.__w = JSON.stringify('no shared worker: ' + e); } 'started'",
    );
    let worker_saw = page_result(app, "window.__w");
    let after = on_main_get(app, || host().map(|h| h.engine_info())).flatten();
    let delta = after
        .as_ref()
        .map(|e| e.worker_requests_blocked)
        .unwrap_or(0)
        .saturating_sub(before.unwrap_or(0));
    push(
        results,
        "requests from workers are blocked too",
        worker_saw == "answered" && delta == 1,
        json!({ "worker_saw": worker_saw, "worker_requests_blocked": delta,
                "worker_requests_tab": after.and_then(|e| e.worker_requests_tab) }),
    );

    // 17. Malware site: warning, then "Continue anyway" for this session.
    on_main(app, || {
        if let Some(h) = host() {
            h.navigate_active("https://malware.canary.untrace.invalid/start");
        }
    });
    sleep(1500);
    let warned = on_main_get(app, active_tab).unwrap_or(Json::Null)["interstitial"].clone();
    on_main(app, || {
        if let Some(h) = host()
            && let Some(id) = h.active_id()
        {
            let _ = h.interstitial_action(id, "continue_threat");
        }
    });
    sleep(2000);
    let after_continue = on_main_get(app, active_tab).unwrap_or(Json::Null)["interstitial"].clone();
    let exceptions = on_main_get(app, || host().map(|h| h.engine_info().threat_session_exceptions)).flatten();
    // The exemption covers that host for the rest of the session, inside other pages too.
    open_probe(app);
    page_eval(app, CANARY_PROBE_JS);
    let seen_later = page_result(app, "window.__m3");
    push(
        results,
        "malware sites are replaced by a warning; continuing lasts the session",
        warned["kind"] == "threat"
            && warned["list"] == "malware"
            && warned["host"] == "malware.canary.untrace.invalid"
            // Let through: the (unresolvable) site now fails to load instead of being stopped.
            && after_continue["kind"] == "load_error"
            && exceptions == Some(1)
            && seen_later["malware"] == "failed"
            && seen_later["phishing"] == "answered",
        json!({ "warning": warned, "after_continue": after_continue, "page_saw_later": seen_later }),
    );

    // 18. Phishing site: warning naming its list; "Go back" leaves.
    on_main(app, || {
        if let Some(h) = host() {
            h.navigate_active("https://login.phishing.canary.untrace.invalid/signin");
        }
    });
    sleep(1500);
    let warned = on_main_get(app, active_tab).unwrap_or(Json::Null)["interstitial"].clone();
    push(
        results,
        "phishing sites are replaced by a warning naming the list",
        warned["kind"] == "threat" && warned["list"] == "phishing" && warned["list_title"] == "Phishing domains",
        warned.clone(),
    );

    // 19. Switching the ads list off (as Settings does) stops it blocking; on restores it.
    open_probe(app);
    let off = set_protection(app, BLOCK_ADS_ID, false);
    page_eval(app, CANARY_PROBE_JS);
    let seen_off = page_result(app, "window.__m3");
    let on = set_protection(app, BLOCK_ADS_ID, true);
    page_eval(app, CANARY_PROBE_JS);
    let seen_on = page_result(app, "window.__m3");
    push(
        results,
        "switching a list off stops it, verified; switching it on restores it",
        off["outcome"] == "verified"
            && seen_off["ads"] == "failed"
            && seen_off["tracker"] == "answered"
            && on["outcome"] == "verified"
            && seen_on["ads"] == "answered",
        json!({ "off": off, "page_saw_off": seen_off, "on": on, "page_saw_on": seen_on }),
    );

    // 20. A site exception stops ads/trackers blocking on that site, not the malware list.
    let site = on_main_get(app, active_tab).unwrap_or(Json::Null)["site"].clone();
    let s = site.as_str().unwrap_or_default().to_string();
    let s2 = s.clone();
    on_main(app, move || {
        if let Some(h) = host() {
            h.set_site_exceptions([s2]);
        }
    });
    page_eval(app, CANARY_PROBE_JS);
    let seen_exc = page_result(app, "window.__m3");
    on_main(app, || {
        if let Some(h) = host() {
            h.set_site_exceptions(Vec::<String>::new());
        }
    });
    push(
        results,
        "a site exception stops ad/tracker blocking there, not malware/phishing blocking",
        !s.is_empty()
            && seen_exc["ads"] == "failed"
            && seen_exc["tracker"] == "failed"
            && seen_exc["phishing"] == "answered", // (malware was continued to in check 17)
        json!({ "site": site, "page_saw": seen_exc }),
    );
}

/// Active tab as JSON (UI thread).
fn active_tab() -> Json {
    host()
        .and_then(|h| {
            let snap = h.snapshot();
            snap.tabs.into_iter().find(|t| Some(t.id) == snap.active)
        })
        .map(|t| serde_json::to_value(t).unwrap_or(Json::Null))
        .unwrap_or(Json::Null)
}

/// Run `f` on the UI thread and wait for its result.
fn on_main_get<T: Send + 'static>(app: &AppHandle, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = app.run_on_main_thread(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(10)).ok()
}

fn run_js(app: &AppHandle, js: &'static str) {
    on_main(app, move || {
        if let Some(h) = host()
            && let Some(id) = h.active_id()
        {
            h.execute(id, js, |_| {});
        }
    });
}

/// Milestone 2: browser security baseline, end to end, still without network access.
fn m2_checks(app: &AppHandle, results: &Results) {
    // 6. HTTPS-only: an http:// address is upgraded; the secure version cannot exist here, so
    //    UNTRACE's own panel must appear, offering plain HTTP — the page must never load over HTTP.
    on_main(app, || {
        if let Some(h) = host() {
            h.navigate_active("http://https-only.untrace.invalid/check");
        }
    });
    sleep(3000);
    let tab = on_main_get(app, active_tab).unwrap_or(Json::Null);
    let inter = &tab["interstitial"];
    let ok = inter["kind"] == "https_unavailable"
        && inter["http_url"] == "http://https-only.untrace.invalid/check"
        && inter["url"] == "https://https-only.untrace.invalid/check";
    push(
        results,
        "HTTPS-only upgrades http:// and explains failures",
        ok,
        inter.clone(),
    );
    on_main(app, || {
        if let Some(h) = host()
            && let Some(id) = h.active_id()
        {
            let _ = h.interstitial_action(id, "back");
        }
    });
    sleep(1500);

    // 7. Scheme gate: a navigation to a local file is cancelled and explained.
    on_main(app, || {
        if let Some(h) = host() {
            h.navigate_active("file:///C:/Windows/win.ini");
        }
    });
    sleep(1000);
    let tab = on_main_get(app, active_tab).unwrap_or(Json::Null);
    let ok = tab["blocked"]["navigations"].as_u64().unwrap_or(0) >= 1
        && !tab["url"].as_str().unwrap_or("").starts_with("file:");
    push(
        results,
        "links to local files are blocked",
        ok,
        json!({ "blocked": tab["blocked"], "notice": tab["notice"], "url": tab["url"] }),
    );

    // 8. External applications: a link type known to be abused is refused without asking.
    run_js(app, "location.href = 'ms-settings:privacy'");
    sleep(1500);
    let tab = on_main_get(app, active_tab).unwrap_or(Json::Null);
    let ok = tab["blocked"]["externalApps"].as_u64().unwrap_or(0) >= 1
        && tab["prompts"].as_array().is_some_and(|p| p.is_empty());
    push(
        results,
        "abused application links are refused without asking",
        ok,
        json!({ "blocked": tab["blocked"], "notice": tab["notice"] }),
    );

    // 9. Permissions: location is asked about; answering "Block" reaches the page as a denial.
    run_js(
        app,
        "window.__geo = 'pending'; navigator.geolocation.getCurrentPosition(() => { window.__geo = 'granted'; }, e => { window.__geo = 'denied:' + e.code; })",
    );
    sleep(1500);
    let tab = on_main_get(app, active_tab).unwrap_or(Json::Null);
    let prompt = tab["prompts"]
        .as_array()
        .and_then(|p| p.iter().find(|p| p["detail"]["permission"] == "geolocation").cloned())
        .unwrap_or(Json::Null);
    let pid = prompt["id"].as_u64();
    if let Some(pid) = pid {
        on_main(app, move || {
            if let Some(h) = host() {
                let _ = h.respond(pid as u32, false, false);
            }
        });
    }
    sleep(1000);
    let geo = on_main_get(app, || {
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        if let Some(h) = host()
            && let Some(id) = h.active_id()
        {
            h.execute(id, "window.__geo", move |j| {
                let _ = tx.send(j);
            });
        }
        rx
    });
    sleep(500);
    let geo = geo.and_then(|rx| rx.try_recv().ok()).unwrap_or_default();
    push(
        results,
        "permission requests are asked about and a refusal reaches the page",
        pid.is_some() && geo.contains("denied:1"),
        json!({ "prompt": prompt, "page_saw": geo }),
    );

    // 10. Downloads: a program is offered for saving only after a question that flags it.
    run_js(
        app,
        "(() => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob(['MZ'], { type: 'application/octet-stream' })); a.download = 'untrace-check.exe'; document.body.appendChild(a); a.click(); })()",
    );
    sleep(2000);
    let tab = on_main_get(app, active_tab).unwrap_or(Json::Null);
    let prompt = tab["prompts"]
        .as_array()
        .and_then(|p| p.iter().find(|p| p["detail"]["type"] == "download").cloned())
        .unwrap_or(Json::Null);
    let ok = prompt["detail"]["file_name"] == "untrace-check.exe" && prompt["detail"]["risk"] == "runs_code";
    if let Some(pid) = prompt["id"].as_u64() {
        on_main(app, move || {
            if let Some(h) = host() {
                let _ = h.respond(pid as u32, false, false);
            }
        });
    }
    sleep(800);
    let after = on_main_get(app, active_tab).unwrap_or(Json::Null);
    let cleared = after["prompts"].as_array().is_some_and(|p| p.is_empty());
    push(
        results,
        "downloads ask first and flag programs",
        ok && cleared,
        json!({ "prompt": prompt }),
    );

    // 11. "Remember for this site" is saved in the profile, listed, and Reset removes it.
    run_js(app, "navigator.geolocation.getCurrentPosition(() => {}, () => {})");
    sleep(1500);
    let tab = on_main_get(app, active_tab).unwrap_or(Json::Null);
    let pid = tab["prompts"]
        .as_array()
        .and_then(|p| p.iter().find(|p| p["detail"]["permission"] == "geolocation"))
        .and_then(|p| p["id"].as_u64());
    if let Some(pid) = pid {
        on_main(app, move || {
            if let Some(h) = host() {
                let _ = h.respond(pid as u32, false, true); // remember the refusal
            }
        });
    }
    sleep(1500);
    let stored = || {
        host()
            .map(|h| h.snapshot().stored_permissions)
            .unwrap_or_default()
            .into_iter()
            // Exactly the origin form the site panel matches on.
            .find(|s| s.origin == format!("https://{PROBE_HOST}") && s.permission == Permission::Geolocation)
    };
    let saved = on_main_get(app, stored).flatten();
    if let Some(s) = saved.clone() {
        on_main(app, move || {
            if let Some(h) = host() {
                let _ = h.reset_permission(&s.origin, Permission::Geolocation);
            }
        });
    }
    sleep(1500);
    let after_reset = on_main_get(app, stored).flatten();
    push(
        results,
        "remembered decisions are saved, listed and can be reset",
        pid.is_some() && saved.as_ref().is_some_and(|s| s.state == "deny") && after_reset.is_none(),
        json!({ "saved": saved.map(|s| json!({ "origin": s.origin, "state": s.state })), "after_reset": after_reset.is_some() }),
    );

    // 12. An accepted download is saved, completes, and carries Mark-of-the-Web. (The Windows
    //     save dialog is replaced by a fixed folder in self-check mode only.)
    let dir = app.state::<AppState>().layout.root.join("self-check-downloads");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    let d2 = dir.clone();
    on_main(app, move || {
        if let Some(h) = host() {
            h.set_test_download_dir(d2);
        }
    });
    run_js(
        app,
        "(() => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob(['UNTRACE save check'], { type: 'text/plain' })); a.download = 'untrace-save-check.txt'; document.body.appendChild(a); a.click(); })()",
    );
    sleep(1500);
    let prompt_id = |tab: &Json, pred: &dyn Fn(&Json) -> bool| {
        tab["prompts"]
            .as_array()
            .and_then(|p| p.iter().find(|p| pred(&p["detail"])))
            .and_then(|p| p["id"].as_u64())
    };
    let answer = |pid: u64| {
        on_main(app, move || {
            if let Some(h) = host() {
                let _ = h.respond(pid as u32, true, false);
            }
        });
    };
    let mut seen = vec![on_main_get(app, active_tab).unwrap_or(Json::Null)["prompts"].clone()];
    // This is the page's second download without a click, so the engine first asks for
    // "download several files"; allow it once (not remembered).
    let tab = on_main_get(app, active_tab).unwrap_or(Json::Null);
    if let Some(m) = prompt_id(&tab, &|d| d["permission"] == "multiple_automatic_downloads") {
        answer(m);
        sleep(1500);
        seen.push(on_main_get(app, active_tab).unwrap_or(Json::Null)["prompts"].clone());
    }
    let tab = on_main_get(app, active_tab).unwrap_or(Json::Null);
    let pid = prompt_id(&tab, &|d| d["type"] == "download");
    if let Some(pid) = pid {
        answer(pid);
    }
    sleep(3000);
    let state = on_main_get(app, || {
        host()
            .and_then(|h| {
                h.snapshot()
                    .downloads
                    .into_iter()
                    .find(|d| d.file_name == "untrace-save-check.txt")
            })
            .map(|d| d.state)
    })
    .flatten();
    let file = dir.join("untrace-save-check.txt");
    let zone = std::fs::read_to_string(format!("{}:Zone.Identifier", file.display())).ok();
    push(
        results,
        "accepted downloads are saved and marked as from the internet",
        pid.is_some()
            && state.as_deref() == Some("completed")
            && file.exists()
            && zone.as_deref().is_some_and(|z| z.contains("ZoneId=3")),
        json!({ "prompts_seen": seen, "state": state, "file_exists": file.exists(), "zone_identifier": zone }),
    );

    // 13. Certificate errors are refused and explained. Needs the HTTPS fixture with a
    //     self-signed certificate (scripts/check.ps1 starts it and sets UNTRACE_SELFCHECK_TLS_URL).
    let name = "certificate errors are refused and explained";
    match std::env::var("UNTRACE_SELFCHECK_TLS_URL") {
        Ok(url) if url.starts_with("https://127.0.0.1:") => {
            let u = url.clone();
            on_main(app, move || {
                if let Some(h) = host() {
                    h.navigate_active(&u);
                }
            });
            sleep(3000);
            let tab = on_main_get(app, active_tab).unwrap_or(Json::Null);
            let inter = &tab["interstitial"];
            let ok = inter["kind"] == "certificate"
                && tab["blocked"]["certificateErrors"].as_u64().unwrap_or(0) >= 1
                && inter["certificate"]["subject"]
                    .as_str()
                    .is_some_and(|s| s.contains("untrace-selfcheck-fixture"));
            push(results, name, ok, inter.clone());
        }
        _ => push_skipped(
            results,
            name,
            "run through scripts/check.ps1, which starts the HTTPS fixture",
        ),
    }
}

/// Capture the window (including WebView2 output) and read pixels.
fn sample(hwnd: HWND, points: &[(i32, i32)]) -> Option<Vec<String>> {
    // SAFETY: GDI capture of our own window into a temporary bitmap; all objects are released.
    unsafe {
        let mut r = RECT::default();
        GetClientRect(hwnd, &mut r).ok()?;
        let wdc = GetDC(Some(hwnd));
        let mdc = CreateCompatibleDC(Some(wdc));
        let bmp = CreateCompatibleBitmap(wdc, r.right, r.bottom);
        let old = SelectObject(mdc, HGDIOBJ(bmp.0));
        let printed = PrintWindow(hwnd, mdc, PRINT_WINDOW_FLAGS(3)).as_bool(); // client only + full content
        let hex = |c: COLORREF| format!("#{:02x}{:02x}{:02x}", c.0 & 0xff, (c.0 >> 8) & 0xff, (c.0 >> 16) & 0xff);
        let out = points.iter().map(|(x, y)| hex(GetPixel(mdc, *x, *y))).collect();
        SelectObject(mdc, old);
        let _ = DeleteObject(HGDIOBJ(bmp.0));
        let _ = DeleteDC(mdc);
        ReleaseDC(Some(hwnd), wdc);
        printed.then_some(out)
    }
}

fn finish(app: &AppHandle, out: &PathBuf, results: &Results) {
    let items = results.lock().unwrap().clone();
    let failed: Vec<String> = items.iter().filter(|i| !i.ok).map(|i| i.name.clone()).collect();
    let passed = failed.is_empty();
    let skipped: Vec<String> = items.iter().filter(|i| i.skipped).map(|i| i.name.clone()).collect();
    let summary: Vec<(String, bool, bool)> = items.iter().map(|i| (i.name.clone(), i.ok, i.skipped)).collect();
    let report = json!({
        "untrace_version": untrace_core::VERSION,
        "at": untrace_core::time::now_rfc3339(),
        "passed": passed,
        "skipped": skipped,
        "protections": coverage_result(&summary),
        "checks": items,
    });
    let _ = std::fs::write(out, serde_json::to_string_pretty(&report).unwrap_or_default());
    let _ = app
        .state::<AppState>()
        .audit
        .record(AuditEvent::SelfCheck { passed, failed });
    let a = app.clone();
    on_main(app, move || a.exit(if passed { 0 } else { 1 }));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M7 exit criterion: every protection in Settings has a self-check of its own.
    #[test]
    fn every_protection_has_a_self_check() {
        for def in crate::protections::defs() {
            let entry = COVERAGE.iter().find(|(id, _)| *id == def.id);
            assert!(
                entry.is_some_and(|(_, names)| !names.is_empty()),
                "no self-check for {}",
                def.id
            );
        }
        for (id, _) in COVERAGE {
            assert!(
                crate::protections::defs().iter().any(|d| d.id == *id),
                "unknown protection {id}"
            );
        }
    }

    #[test]
    fn protection_results_follow_their_checks() {
        let checks = vec![
            ("developer tools read back as off".to_string(), true, false),
            (
                "tracking parameters are removed before the request leaves".to_string(),
                false,
                false,
            ),
            (
                "closing UNTRACE deletes what its switches say, checked".to_string(),
                true,
                true,
            ),
        ];
        let r = coverage_result(&checks);
        let of = |id: &str| {
            r.iter().find(|x| x["id"] == id).unwrap()["state"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(of("browser.devtools"), "passed");
        assert_eq!(of("privacy.strip_tracking_params"), "failed");
        assert_eq!(of("privacy.clear_cache_on_exit"), "not_run");
        assert_eq!(of("network.doh_provider"), "not_run");
    }
}
