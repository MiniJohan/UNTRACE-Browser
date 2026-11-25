//! HTTPS downloads for block-list updates, using Windows' own HTTP client (WinHTTP, D-020:
//! platform APIs before new dependencies). Blocking; call from a worker thread only.
//!
//! - HTTPS only, TLS 1.2 or newer, certificate checks left to Windows (never relaxed).
//! - Redirects to plain HTTP are refused (WinHTTP's default policy, set explicitly).
//! - No cookies, no referrer, no identifying headers beyond a generic user agent.
//! - The body is capped; a larger download is abandoned, not truncated.

use windows::{Win32::Networking::WinHttp::*, core::*};

pub struct Response {
    pub status: u32,
    pub body: Vec<u8>,
}

/// A WinHTTP handle closed on drop.
struct Handle(*mut core::ffi::c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: closing a handle WinHTTP gave us, exactly once.
            unsafe {
                let _ = WinHttpCloseHandle(self.0);
            }
        }
    }
}

fn open(h: *mut core::ffi::c_void, what: &str) -> std::result::Result<Handle, String> {
    if h.is_null() {
        Err(format!("{what}: {}", Error::from_thread().message()))
    } else {
        Ok(Handle(h))
    }
}

/// GET an `https://` URL. Errors are short, user-readable sentences.
pub fn get(url: &str, max_bytes: usize) -> std::result::Result<Response, String> {
    let u = url::Url::parse(url).map_err(|_| "invalid address".to_string())?;
    if u.scheme() != "https" {
        return Err("only HTTPS addresses are used".into());
    }
    let host = u.host_str().ok_or("invalid address")?.to_string();
    let port = u.port().unwrap_or(443);
    let path = match u.query() {
        Some(q) => format!("{}?{q}", u.path()),
        None => u.path().to_string(),
    };

    // SAFETY (whole block): plain WinHTTP calls on handles owned by `Handle` guards; buffers
    // outlive the calls that write into them.
    unsafe {
        let session = open(
            WinHttpOpen(
                w!("UNTRACE"),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                PCWSTR::null(),
                PCWSTR::null(),
                0,
            ),
            "could not start the download",
        )?;
        // Resolve, connect, send: 15 s each; receive: 30 s between chunks.
        let _ = WinHttpSetTimeouts(session.0, 15_000, 15_000, 15_000, 30_000);
        let tls = (WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3).to_le_bytes();
        let _ = WinHttpSetOption(Some(session.0), WINHTTP_OPTION_SECURE_PROTOCOLS, Some(&tls));
        let connect = open(
            WinHttpConnect(session.0, &HSTRING::from(host.as_str()), port, 0),
            "could not reach the server",
        )?;
        let request = open(
            WinHttpOpenRequest(
                connect.0,
                w!("GET"),
                &HSTRING::from(path.as_str()),
                PCWSTR::null(),
                PCWSTR::null(),
                std::ptr::null(),
                WINHTTP_FLAG_SECURE,
            ),
            "could not start the request",
        )?;
        let no_cookies = WINHTTP_DISABLE_COOKIES.to_le_bytes();
        let _ = WinHttpSetOption(Some(request.0), WINHTTP_OPTION_DISABLE_FEATURE, Some(&no_cookies));
        let policy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP.to_le_bytes();
        let _ = WinHttpSetOption(Some(request.0), WINHTTP_OPTION_REDIRECT_POLICY, Some(&policy));

        WinHttpSendRequest(request.0, None, None, 0, 0, 0).map_err(|e| format!("request failed: {}", e.message()))?;
        WinHttpReceiveResponse(request.0, std::ptr::null_mut()).map_err(|e| format!("no response: {}", e.message()))?;

        let mut status = 0u32;
        let mut len = std::mem::size_of::<u32>() as u32;
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some(&mut status as *mut u32 as *mut _),
            &mut len,
            std::ptr::null_mut(),
        )
        .map_err(|e| format!("unreadable response: {}", e.message()))?;

        let mut body = Vec::new();
        loop {
            let mut available = 0u32;
            WinHttpQueryDataAvailable(request.0, &mut available)
                .map_err(|e| format!("download interrupted: {}", e.message()))?;
            if available == 0 {
                break;
            }
            if body.len() + available as usize > max_bytes {
                return Err(format!("the download is larger than {} MB", max_bytes / (1024 * 1024)));
            }
            let start = body.len();
            body.resize(start + available as usize, 0);
            let mut read = 0u32;
            WinHttpReadData(request.0, body[start..].as_mut_ptr() as *mut _, available, &mut read)
                .map_err(|e| format!("download interrupted: {}", e.message()))?;
            body.truncate(start + read as usize);
        }
        Ok(Response { status, body })
    }
}
