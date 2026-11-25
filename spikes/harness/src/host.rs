//! Minimal WebView2 host: a plain Win32 window, environment/controller creation and
//! synchronous-style helpers (navigate, execute script, DevTools protocol) for spikes.

use std::{path::Path, sync::mpsc, time::Duration};

use webview2_com::{Microsoft::Web::WebView2::Win32::*, *};
use windows::{
    core::*,
    Win32::{
        Foundation::*,
        System::{Com::IStream, LibraryLoader::GetModuleHandleW},
        UI::{Shell::SHCreateMemStream, WindowsAndMessaging::*},
    },
};

use crate::pump;

pub const T: Duration = Duration::from_secs(20);

extern "system" fn wndproc(h: HWND, m: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    unsafe { DefWindowProcW(h, m, w, l) }
}

pub fn create_window(title: &str, w: i32, h: i32) -> HWND {
    unsafe {
        let hinst = HINSTANCE(GetModuleHandleW(None).expect("module").0);
        let class = w!("UntraceSpikeWindow");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            lpszClassName: class,
            hInstance: hinst,
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            ..Default::default()
        };
        RegisterClassW(&wc); // fails harmlessly if already registered
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            &HSTRING::from(title),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            40,
            40,
            w,
            h,
            None,
            None,
            Some(hinst),
            None,
        )
        .expect("CreateWindowExW")
    }
}

pub fn destroy_window(hwnd: HWND) {
    unsafe {
        let _ = DestroyWindow(hwnd);
    }
}

#[derive(Clone, Default)]
pub struct EnvOpts {
    pub args: String,
    pub extensions: bool,
    pub tracking_prevention: bool,
    pub crash_local: bool,
}

pub fn create_env(udf: &Path, o: &EnvOpts) -> ICoreWebView2Environment {
    let options = CoreWebView2EnvironmentOptions::default();
    unsafe {
        options.set_additional_browser_arguments(o.args.clone());
        options.set_are_browser_extensions_enabled(o.extensions);
        options.set_enable_tracking_prevention(o.tracking_prevention);
        options.set_is_custom_crash_reporting_enabled(o.crash_local);
    }
    let options: ICoreWebView2EnvironmentOptions = options.into();
    let udf_h = HSTRING::from(udf.as_os_str());
    let (tx, rx) = mpsc::channel();
    CreateCoreWebView2EnvironmentCompletedHandler::wait_for_async_operation(
        Box::new(move |handler| unsafe {
            CreateCoreWebView2EnvironmentWithOptions(PCWSTR::null(), &udf_h, &options, &handler)
                .map_err(webview2_com::Error::WindowsError)
        }),
        Box::new(move |hr, env| {
            hr?;
            tx.send(env.expect("environment")).expect("send");
            Ok(())
        }),
    )
    .expect("create environment");
    rx.recv().expect("environment")
}

pub fn create_controller(
    env: &ICoreWebView2Environment,
    hwnd: HWND,
    profile: &str,
    inprivate: bool,
) -> ICoreWebView2Controller {
    let env10: ICoreWebView2Environment10 = env.cast().expect("Environment10");
    let opts = unsafe { env10.CreateCoreWebView2ControllerOptions().expect("controller options") };
    unsafe {
        opts.SetProfileName(&HSTRING::from(profile)).expect("profile name");
        opts.SetIsInPrivateModeEnabled(inprivate).expect("inprivate");
    }
    let (tx, rx) = mpsc::channel();
    CreateCoreWebView2ControllerCompletedHandler::wait_for_async_operation(
        Box::new(move |h| unsafe {
            env10
                .CreateCoreWebView2ControllerWithOptions(hwnd, &opts, &h)
                .map_err(webview2_com::Error::WindowsError)
        }),
        Box::new(move |hr, c| {
            hr?;
            tx.send(c.expect("controller")).expect("send");
            Ok(())
        }),
    )
    .expect("create controller");
    let c = rx.recv().expect("controller");
    fit(&c, hwnd);
    unsafe { c.SetIsVisible(true).expect("visible") };
    c
}

pub fn fit(c: &ICoreWebView2Controller, hwnd: HWND) {
    unsafe {
        let mut r = RECT::default();
        let _ = GetClientRect(hwnd, &mut r);
        let _ = c.SetBounds(r);
    }
}

pub fn webview(c: &ICoreWebView2Controller) -> ICoreWebView2 {
    unsafe { c.CoreWebView2().expect("CoreWebView2") }
}

pub fn take(p: PWSTR) -> String {
    CoTaskMemPWSTR::from(p).to_string()
}

pub fn browser_version(env: &ICoreWebView2Environment) -> String {
    let mut p = PWSTR::null();
    unsafe { env.BrowserVersionString(&mut p).expect("version") };
    take(p)
}

#[derive(Debug, Clone)]
pub struct Nav {
    pub ok: bool,
    pub status: i32,
}

pub fn navigate(wv: &ICoreWebView2, url: &str, timeout: Duration) -> Option<Nav> {
    let (tx, rx) = mpsc::channel();
    let mut token = 0i64;
    let h = NavigationCompletedEventHandler::create(Box::new(move |_s, args| {
        if let Some(a) = args {
            let mut ok = BOOL(0);
            let mut st = COREWEBVIEW2_WEB_ERROR_STATUS(0);
            unsafe {
                a.IsSuccess(&mut ok)?;
                a.WebErrorStatus(&mut st)?;
            }
            let _ = tx.send(Nav { ok: ok.as_bool(), status: st.0 });
        }
        Ok(())
    }));
    unsafe {
        wv.add_NavigationCompleted(&h, &mut token).expect("add nav completed");
        if wv.Navigate(&HSTRING::from(url)).is_err() {
            let _ = wv.remove_NavigationCompleted(token);
            return None;
        }
    }
    let r = pump::wait(&rx, timeout);
    unsafe {
        let _ = wv.remove_NavigationCompleted(token);
    }
    r
}

/// Execute script; returns the JSON-encoded result (or an "ERR …" string).
pub fn exec(wv: &ICoreWebView2, js: &str) -> String {
    let (tx, rx) = mpsc::channel();
    let h = ExecuteScriptCompletedHandler::create(Box::new(move |hr, result| {
        let _ = tx.send(match hr {
            Ok(()) => result,
            Err(e) => format!("\"ERR {e:?}\""),
        });
        Ok(())
    }));
    unsafe {
        if let Err(e) = wv.ExecuteScript(&HSTRING::from(js), &h) {
            return format!("\"ERR {e:?}\"");
        }
    }
    pump::wait(&rx, T).unwrap_or_else(|| "\"ERR timeout\"".into())
}

/// Execute script and parse its JSON result.
pub fn exec_json(wv: &ICoreWebView2, js: &str) -> serde_json::Value {
    let s = exec(wv, js);
    serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s))
}

/// Poll `document.title` until it equals `title`.
pub fn wait_title(wv: &ICoreWebView2, title: &str, timeout: Duration) -> bool {
    let want = format!("\"{title}\"");
    pump::until(timeout, || exec(wv, "document.title") == want)
}

pub fn cdp(wv: &ICoreWebView2, method: &str, params: &str) -> std::result::Result<String, String> {
    let (tx, rx) = mpsc::channel();
    let h = CallDevToolsProtocolMethodCompletedHandler::create(Box::new(move |hr, json| {
        let _ = tx.send(match hr {
            Ok(()) => Ok(json),
            Err(e) => Err(format!("{e:?} {json}")),
        });
        Ok(())
    }));
    unsafe {
        wv.CallDevToolsProtocolMethod(&HSTRING::from(method), &HSTRING::from(params), &h)
            .map_err(|e| format!("{e:?}"))?;
    }
    pump::wait(&rx, T).unwrap_or_else(|| Err("timeout".into()))
}

pub fn add_init_script(wv: &ICoreWebView2, js: &str) -> std::result::Result<String, String> {
    let (tx, rx) = mpsc::channel();
    let h = AddScriptToExecuteOnDocumentCreatedCompletedHandler::create(Box::new(move |hr, id| {
        let _ = tx.send(hr.map(|_| id).map_err(|e| format!("{e:?}")));
        Ok(())
    }));
    unsafe {
        wv.AddScriptToExecuteOnDocumentCreated(&HSTRING::from(js), &h)
            .map_err(|e| format!("{e:?}"))?;
    }
    pump::wait(&rx, T).unwrap_or_else(|| Err("timeout".into()))
}

/// Content-view hardening used by UNTRACE: no host bridge.
pub fn harden(wv: &ICoreWebView2) {
    unsafe {
        let s = wv.Settings().expect("settings");
        s.SetIsWebMessageEnabled(false).expect("web message");
        s.SetAreHostObjectsAllowed(false).expect("host objects");
    }
}

pub fn stream(bytes: &[u8]) -> Option<IStream> {
    unsafe { SHCreateMemStream(Some(bytes)) }
}

pub fn make_response(
    env: &ICoreWebView2Environment,
    status: i32,
    reason: &str,
    headers: &str,
    body: &[u8],
) -> ICoreWebView2WebResourceResponse {
    let s = stream(body);
    unsafe {
        env.CreateWebResourceResponse(
            s.as_ref(),
            status,
            &HSTRING::from(reason),
            &HSTRING::from(headers),
        )
        .expect("response")
    }
}

/// Accept certificate errors for spike fixtures (*.test hosts only). TEST-ONLY behaviour.
pub fn allow_fixture_certs(wv: &ICoreWebView2) {
    let wv14: ICoreWebView2_14 = wv.cast().expect("WebView2_14");
    let mut token = 0i64;
    let h = ServerCertificateErrorDetectedEventHandler::create(Box::new(move |_s, args| {
        if let Some(a) = args {
            let mut p = PWSTR::null();
            unsafe { a.RequestUri(&mut p)? };
            let uri = take(p);
            let host_ok = uri
                .split("://")
                .nth(1)
                .and_then(|r| r.split(['/', ':']).next())
                .map(|h| h.ends_with(".test") || h.ends_with(".doubleclick.net"))
                .unwrap_or(false);
            unsafe {
                a.SetAction(if host_ok {
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

/// Supply proxy credentials when WebView2 asks for them (only for the given proxy port).
pub fn proxy_credentials(wv: &ICoreWebView2, port: u16, user: &str, pass: &str) {
    let wv10: ICoreWebView2_10 = wv.cast().expect("WebView2_10");
    let (user, pass) = (user.to_string(), pass.to_string());
    let needle = format!(":{port}");
    let mut token = 0i64;
    let h = BasicAuthenticationRequestedEventHandler::create(Box::new(move |_s, args| {
        if let Some(a) = args {
            let mut p = PWSTR::null();
            unsafe { a.Uri(&mut p)? };
            let uri = take(p);
            crate::note(&format!("auth requested for {uri}"));
            unsafe {
                if uri.contains("127.0.0.1") && uri.contains(&needle) {
                    let r = a.Response()?;
                    r.SetUserName(&HSTRING::from(user.as_str()))?;
                    r.SetPassword(&HSTRING::from(pass.as_str()))?;
                } else {
                    a.SetCancel(true)?;
                }
            }
        }
        Ok(())
    }));
    unsafe { wv10.add_BasicAuthenticationRequested(&h, &mut token).expect("auth handler") };
}

pub fn close(c: ICoreWebView2Controller) {
    unsafe {
        let _ = c.Close();
    }
}
