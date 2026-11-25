//! S1 - Tauri shell + raw WebView2 content view (separate environment, no host bridge).
//! A driver thread walks through the checks; WebView2 work runs on the main thread via
//! `run_on_main_thread`. Results: <results dir>/s1.json, plus an `s1.ready` marker so an
//! external script can measure process memory while both environments are alive.

use std::{
    cell::RefCell,
    path::PathBuf,
    sync::atomic::{AtomicIsize, Ordering},
    thread,
    time::Duration,
};

use serde_json::{json, Map, Value};
use tauri::{AppHandle, Manager, WindowEvent};
use webview2_com::{Microsoft::Web::WebView2::Win32::*, *};
use windows::{
    core::*,
    Win32::{
        Foundation::*,
        Graphics::Gdi::*,
        Storage::Xps::{PrintWindow, PRINT_WINDOW_FLAGS},
        UI::{HiDpi::GetDpiForWindow, Input::KeyboardAndMouse::*, WindowsAndMessaging::*},
    },
};

const BAR_DIP: f64 = 48.0;
const CONTENT_HOST: &str = "content.untrace-spike.test";

static HWND_RAW: AtomicIsize = AtomicIsize::new(0);
static HOST_RAW: AtomicIsize = AtomicIsize::new(0); // optional container child window

fn use_container() -> bool {
    std::env::var("S1_CONTAINER").map(|v| v == "1").unwrap_or(false)
}

extern "system" fn host_proc(h: HWND, m: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    unsafe { DefWindowProcW(h, m, w, l) }
}

/// A plain child window, top of the sibling z-order, that parents the content controller.
fn create_container(parent: HWND) -> HWND {
    unsafe {
        let class = w!("UntraceContentHost");
        let wc = WNDCLASSW { lpfnWndProc: Some(host_proc), lpszClassName: class, ..Default::default() };
        RegisterClassW(&wc);
        let h = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            w!(""),
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
            0, 0, 10, 10,
            Some(parent),
            None,
            None,
            None,
        )
        .expect("container");
        let _ = SetWindowPos(h, Some(HWND_TOP), 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        h
    }
}

fn class_of(h: HWND) -> String {
    let mut buf = [0u16; 128];
    let n = unsafe { GetClassNameW(h, &mut buf) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

/// Direct children of the main window, top of z-order first.
fn zorder() -> Vec<String> {
    let mut out = vec![];
    unsafe {
        let mut c = GetWindow(hwnd(), GW_CHILD).unwrap_or_default();
        while !c.0.is_null() {
            let mut r = RECT::default();
            let _ = GetWindowRect(c, &mut r);
            let mine = c.0 as isize == HOST_RAW.load(Ordering::SeqCst);
            out.push(format!("{}{} visible={} rect=({},{},{},{})", class_of(c), if mine { " [UNTRACE container]" } else { "" }, IsWindowVisible(c).as_bool(), r.left, r.top, r.right, r.bottom));
            c = GetWindow(c, GW_HWNDNEXT).unwrap_or_default();
        }
    }
    out
}

thread_local! {
    static CTRL: RefCell<Option<ICoreWebView2Controller>> = const { RefCell::new(None) };
    static RESULTS: RefCell<Map<String, Value>> = RefCell::new(Map::new());
    static KEYS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn hwnd() -> HWND {
    HWND(HWND_RAW.load(Ordering::SeqCst) as *mut _)
}

fn put(k: &str, v: Value) {
    RESULTS.with(|r| r.borrow_mut().insert(k.into(), v));
}

fn bar_px(h: HWND) -> i32 {
    let dpi = unsafe { GetDpiForWindow(h) } as f64;
    (BAR_DIP * dpi / 96.0).round() as i32
}

fn relayout() {
    let h = hwnd();
    if h.0.is_null() {
        return;
    }
    let mut r = RECT::default();
    unsafe {
        let _ = GetClientRect(h, &mut r);
    }
    let mut bounds = RECT { left: 0, top: bar_px(h), right: r.right, bottom: r.bottom };
    let host = HWND(HOST_RAW.load(Ordering::SeqCst) as *mut _);
    if !host.0.is_null() {
        unsafe {
            let _ = SetWindowPos(
                host,
                Some(HWND_TOP),
                bounds.left,
                bounds.top,
                bounds.right - bounds.left,
                bounds.bottom - bounds.top,
                SWP_NOACTIVATE,
            );
        }
        bounds = RECT { left: 0, top: 0, right: bounds.right - bounds.left, bottom: bounds.bottom - bounds.top };
    }
    CTRL.with(|c| {
        if let Some(c) = c.borrow().as_ref() {
            unsafe {
                let _ = c.SetBounds(bounds);
            }
        }
    });
}

fn content_html() -> &'static str {
    r#"<!doctype html><html><head><meta charset=utf-8><style>html,body{margin:0;height:100%;background:#00a000}</style></head><body>
<script>
(async () => {
  const c = window.chrome;
  const p = {
    tauri_internals: typeof window.__TAURI_INTERNALS__,
    tauri_global: typeof window.__TAURI__,
    window_ipc: typeof window.ipc,
    chrome_webview: typeof (c && c.webview),
    chrome_webview_postMessage: typeof (c && c.webview && c.webview.postMessage),
    chrome_webview_hostObjects: typeof (c && c.webview && c.webview.hostObjects),
    chrome_keys: c ? Object.keys(c) : null,
    user_agent: navigator.userAgent,
    ua_brands: navigator.userAgentData ? navigator.userAgentData.brands : null,
  };
  try { p.ua_high_entropy = await navigator.userAgentData.getHighEntropyValues(['fullVersionList', 'platformVersion', 'architecture']); } catch (e) { p.ua_high_entropy = String(e); }
  window.__probe = p;
})();
</script></body></html>"#
}

fn create_content(h: HWND, udf: PathBuf) {
    let folder = udf.join(format!("s1-content-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&folder);
    std::fs::write(folder.join("index.html"), content_html()).expect("content html");
    let options = CoreWebView2EnvironmentOptions::default();
    unsafe {
        options.set_enable_tracking_prevention(true);
        options.set_is_custom_crash_reporting_enabled(true);
    }
    let options: ICoreWebView2EnvironmentOptions = options.into();
    let udf_h = HSTRING::from(udf.join(format!("s1c-{}", std::process::id())).as_os_str());
    let handler = CreateCoreWebView2EnvironmentCompletedHandler::create(Box::new(move |hr, env| {
        hr?;
        let env = env.expect("env");
        let folder = folder.clone();
        let ch = CreateCoreWebView2ControllerCompletedHandler::create(Box::new(move |hr, c| {
            hr?;
            let c = c.expect("controller");
            let wv = unsafe { c.CoreWebView2()? };
            unsafe {
                let s = wv.Settings()?;
                s.SetIsWebMessageEnabled(false)?;
                s.SetAreHostObjectsAllowed(false)?;
                let w3: ICoreWebView2_3 = wv.cast()?;
                w3.SetVirtualHostNameToFolderMapping(
                    &HSTRING::from(CONTENT_HOST),
                    &HSTRING::from(folder.as_os_str()),
                    COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_DENY_CORS,
                )?;
                let mut tok = 0i64;
                c.add_AcceleratorKeyPressed(
                    &AcceleratorKeyPressedEventHandler::create(Box::new(|_c, args| {
                        if let Some(a) = args {
                            let mut kind = COREWEBVIEW2_KEY_EVENT_KIND(0);
                            let mut vk = 0u32;
                            a.KeyEventKind(&mut kind)?;
                            a.VirtualKey(&mut vk)?;
                            let ctrl = GetKeyState(VK_CONTROL.0 as i32) < 0;
                            KEYS.with(|k| k.borrow_mut().push(format!("kind={} vk=0x{vk:02X} ctrl={ctrl}", kind.0)));
                        }
                        Ok(())
                    })),
                    &mut tok,
                )?;
                c.SetIsVisible(true)?;
            }
            CTRL.with(|x| *x.borrow_mut() = Some(c.clone()));
            relayout();
            unsafe { wv.Navigate(&HSTRING::from(format!("https://{CONTENT_HOST}/index.html")))? };
            put("content_view_created", json!(true));
            Ok(())
        }));
        let parent = if use_container() {
            let c = create_container(h);
            HOST_RAW.store(c.0 as isize, Ordering::SeqCst);
            c
        } else {
            h
        };
        unsafe { env.CreateCoreWebView2Controller(parent, &ch)? };
        Ok(())
    }));
    unsafe {
        CreateCoreWebView2EnvironmentWithOptions(PCWSTR::null(), &udf_h, &options, &handler).expect("environment");
    }
}

fn with_webview(f: impl FnOnce(&ICoreWebView2)) {
    CTRL.with(|c| {
        if let Some(c) = c.borrow().as_ref() {
            if let Ok(wv) = unsafe { c.CoreWebView2() } {
                f(&wv);
            }
        }
    });
}

fn read_probe(key: &'static str) {
    with_webview(|wv| {
        let h = ExecuteScriptCompletedHandler::create(Box::new(move |_hr, json| {
            put(key, serde_json::from_str(&json).unwrap_or(Value::String(json)));
            Ok(())
        }));
        unsafe {
            let _ = wv.ExecuteScript(w!("window.__probe || null"), &h);
        }
    });
}

fn hex(c: COLORREF) -> String {
    let v = c.0;
    format!("#{:02x}{:02x}{:02x}", v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff)
}

fn pixels(label: &str) {
    let h = hwnd();
    let mut r = RECT::default();
    unsafe {
        let _ = GetClientRect(h, &mut r);
        let (w, ht) = (r.right, r.bottom);
        let wdc = GetDC(Some(h));
        let mdc = CreateCompatibleDC(Some(wdc));
        let bmp = CreateCompatibleBitmap(wdc, w, ht);
        let old = SelectObject(mdc, HGDIOBJ(bmp.0));
        let printed = PrintWindow(h, mdc, PRINT_WINDOW_FLAGS(3)).as_bool(); // CLIENTONLY | RENDERFULLCONTENT
        let bar = bar_px(h);
        let sample = |x: i32, y: i32| hex(GetPixel(mdc, x, y));
        let mut bounds = RECT::default();
        CTRL.with(|c| {
            if let Some(c) = c.borrow().as_ref() {
                let _ = c.Bounds(&mut bounds);
            }
        });
        put(
            &format!("pixels_{label}"),
            json!({
                "client": [w, ht], "bar_px": bar, "printwindow_ok": printed,
                "controller_bounds": [bounds.left, bounds.top, bounds.right, bounds.bottom],
                "container_mode": use_container(),
                "child_zorder_top_first": zorder(),
                "bar_center": sample(w / 2, bar / 2),
                "content_center": sample(w / 2, (bar + ht) / 2),
                "content_bottom_right": sample(w - 8, ht - 8),
                "expect": { "bar": "#202020", "content": "#00a000", "uncovered_ui": "#ff00ff" },
            }),
        );
        SelectObject(mdc, old);
        let _ = DeleteObject(HGDIOBJ(bmp.0));
        let _ = DeleteDC(mdc);
        ReleaseDC(Some(h), wdc);
    }
}

fn resize() {
    unsafe {
        let _ = SetWindowPos(hwnd(), None, 0, 0, 900, 620, SWP_NOMOVE | SWP_NOZORDER);
    }
}

fn key(vk: VIRTUAL_KEY, up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT { wVk: vk, wScan: 0, dwFlags: if up { KEYEVENTF_KEYUP } else { KEYBD_EVENT_FLAGS(0) }, time: 0, dwExtraInfo: 0 },
        },
    }
}

fn keys() {
    let h = hwnd();
    CTRL.with(|c| {
        if let Some(c) = c.borrow().as_ref() {
            unsafe {
                let _ = c.MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
            }
        }
    });
    unsafe {
        let fg = SetForegroundWindow(h).as_bool();
        let is_fg = GetForegroundWindow() == h;
        put("foreground", json!({ "set_foreground_ok": fg, "is_foreground": is_fg }));
        let seq = [
            key(VK_CONTROL, false), key(VIRTUAL_KEY(b'L' as u16), false), key(VIRTUAL_KEY(b'L' as u16), true),
            key(VIRTUAL_KEY(b'T' as u16), false), key(VIRTUAL_KEY(b'T' as u16), true), key(VK_CONTROL, true),
        ];
        let sent = SendInput(&seq, std::mem::size_of::<INPUT>() as i32);
        put("sendinput_events", json!(sent));
    }
}

fn enable_bridge_and_reload() {
    with_webview(|wv| unsafe {
        if let Ok(s) = wv.Settings() {
            let _ = s.SetIsWebMessageEnabled(true);
            let _ = s.SetAreHostObjectsAllowed(true);
        }
        let _ = wv.Reload();
    });
}

fn write(out: PathBuf) {
    KEYS.with(|k| put("accelerator_keys_seen", json!(k.borrow().clone())));
    let tauri_version = tauri::VERSION;
    put("tauri_version", json!(tauri_version));
    put("pid", json!(std::process::id()));
    let text = RESULTS.with(|r| serde_json::to_string_pretty(&Value::Object(r.borrow().clone())).unwrap());
    let name = if use_container() { "s1-container.json" } else { "s1.json" };
    std::fs::write(out.join(name), text).expect("write s1 results");
    std::fs::write(out.join("s1.ready"), "ready").expect("ready marker");
}

fn on_main(app: &AppHandle, f: impl FnOnce() + Send + 'static) {
    let _ = app.run_on_main_thread(f);
}

fn driver(app: AppHandle, out: PathBuf) {
    let s = |ms| thread::sleep(Duration::from_millis(ms));
    s(4000);
    on_main(&app, || read_probe("content_probe_hardened"));
    s(800);
    on_main(&app, || pixels("initial"));
    on_main(&app, resize);
    s(1500);
    on_main(&app, || pixels("after_resize"));
    on_main(&app, keys);
    s(1500);
    on_main(&app, enable_bridge_and_reload);
    s(2500);
    on_main(&app, || read_probe("content_probe_bridge_enabled"));
    s(800);
    let o = out.clone();
    on_main(&app, move || write(o));
    s(12000); // window for the external memory measurement
    app.exit(0);
}

fn main() {
    let out = PathBuf::from(std::env::args().nth(1).expect("results dir argument"));
    let udf = PathBuf::from(std::env::var("UNTRACE_SPIKE_UDF").expect("UNTRACE_SPIKE_UDF"));
    tauri::Builder::default()
        .setup(move |app| {
            let win = app.get_webview_window("main").expect("main window");
            let h = HWND(win.hwnd()?.0 as *mut _);
            HWND_RAW.store(h.0 as isize, Ordering::SeqCst);
            create_content(h, udf.clone());
            let handle = app.handle().clone();
            let out = out.clone();
            thread::spawn(move || driver(handle, out));
            Ok(())
        })
        .on_window_event(|_w, e| {
            if matches!(e, WindowEvent::Resized(_) | WindowEvent::ScaleFactorChanged { .. }) {
                relayout();
            }
        })
        .run(tauri::generate_context!())
        .expect("tauri run");
}
