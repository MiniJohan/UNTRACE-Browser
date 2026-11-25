//! Message pumping helpers. WebView2 delivers every callback through the UI thread's
//! message queue, so any wait on the UI thread must keep dispatching messages.

use std::{
    sync::mpsc,
    time::{Duration, Instant},
};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, MsgWaitForMultipleObjects, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
    QS_ALLINPUT,
};

/// Dispatch pending messages, then sleep until a new message arrives or `max_wait` passes.
pub fn pump_once(max_wait: Duration) {
    unsafe {
        let mut msg = MSG::default();
        let mut n = 0;
        while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
            n += 1;
            if n > 500 {
                break;
            }
        }
        MsgWaitForMultipleObjects(None, false, max_wait.as_millis() as u32, QS_ALLINPUT);
    }
}

/// Wait for a value on `rx` while pumping messages. `None` on timeout.
pub fn wait<T>(rx: &mpsc::Receiver<T>, timeout: Duration) -> Option<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(v) = rx.try_recv() {
            return Some(v);
        }
        if Instant::now() >= deadline {
            return None;
        }
        pump_once(Duration::from_millis(5));
    }
}

/// Pump messages for `d`.
pub fn sleep(d: Duration) {
    let deadline = Instant::now() + d;
    while Instant::now() < deadline {
        pump_once(Duration::from_millis(5));
    }
}

/// Pump until `cond` is true or the timeout passes. Returns whether `cond` became true.
pub fn until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        pump_once(Duration::from_millis(10));
    }
    cond()
}
