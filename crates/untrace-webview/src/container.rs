//! The UNTRACE content container: a plain child window of the app window, kept at the top of
//! the sibling z-order, that parents every content controller. Without it the content views
//! end up beneath Tauri's own webview (M0/S1).
//!
//! It also provides [`defer`]: run a closure on a later turn of the message loop, so actions
//! triggered from inside a WebView2 event (closing the tab that raised it, for example) never
//! re-enter the runtime.

use std::cell::RefCell;

use windows::{
    Win32::{
        Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM},
        System::LibraryLoader::GetModuleHandleW,
        UI::WindowsAndMessaging::*,
    },
    core::{Result, w},
};

const WM_RUN_DEFERRED: u32 = WM_APP + 0x51;

type Job = Box<dyn FnOnce()>;

thread_local! {
    static DEFERRED: RefCell<Vec<Job>> = RefCell::new(Vec::new());
    static CONTAINER: RefCell<Option<isize>> = const { RefCell::new(None) };
    static TIMED: RefCell<Vec<(usize, Job)>> = RefCell::new(Vec::new());
    static NEXT_TIMER: std::cell::Cell<usize> = const { std::cell::Cell::new(1) };
}

extern "system" fn wndproc(h: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    if msg == WM_TIMER {
        let id = w.0;
        // SAFETY: stopping our own one-shot timer.
        unsafe {
            let _ = KillTimer(Some(h), id);
        }
        let job = TIMED.with(|t| {
            let mut t = t.borrow_mut();
            t.iter().position(|(i, _)| *i == id).map(|p| t.remove(p).1)
        });
        if let Some(job) = job {
            job();
        }
        return LRESULT(0);
    }
    if msg == WM_RUN_DEFERRED {
        let jobs: Vec<Box<dyn FnOnce()>> = DEFERRED.with(|d| std::mem::take(&mut *d.borrow_mut()));
        for job in jobs {
            job();
        }
        return LRESULT(0);
    }
    if msg == WM_ERASEBKGND {
        return LRESULT(1); // controllers paint everything; avoid flashes
    }
    // SAFETY: forwarding an unhandled message to the default window procedure.
    unsafe { DefWindowProcW(h, msg, w, l) }
}

pub fn create(parent: HWND) -> Result<HWND> {
    // SAFETY: plain Win32 window-class registration and child-window creation on the UI thread.
    unsafe {
        let hinst = HINSTANCE(GetModuleHandleW(None)?.0);
        let class = w!("UntraceContentContainer");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            lpszClassName: class,
            hInstance: hinst,
            ..Default::default()
        };
        RegisterClassW(&wc); // a second registration fails harmlessly
        let h = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            w!(""),
            WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
            0,
            0,
            1,
            1,
            Some(parent),
            None,
            Some(hinst),
            None,
        )?;
        CONTAINER.with(|c| *c.borrow_mut() = Some(h.0 as isize));
        Ok(h)
    }
}

/// Run `f` on the UI thread after about `ms` milliseconds (a one-shot timer on the container).
/// Dropped silently if the container does not exist.
pub fn defer_after(ms: u32, f: impl FnOnce() + 'static) {
    let Some(h) = CONTAINER.with(|c| *c.borrow()) else {
        return;
    };
    let id = NEXT_TIMER.with(|n| {
        let id = n.get();
        n.set(id + 1);
        id
    });
    TIMED.with(|t| t.borrow_mut().push((id, Box::new(f))));
    // SAFETY: a timer on our own window; WM_TIMER arrives on this thread.
    unsafe {
        SetTimer(Some(HWND(h as *mut _)), id, ms, None);
    }
}

/// Run `f` on a later turn of the UI thread's message loop.
pub fn defer(f: impl FnOnce() + 'static) {
    DEFERRED.with(|d| d.borrow_mut().push(Box::new(f)));
    if let Some(h) = CONTAINER.with(|c| *c.borrow()) {
        // SAFETY: posting a private message to our own window.
        unsafe {
            let _ = PostMessageW(Some(HWND(h as *mut _)), WM_RUN_DEFERRED, WPARAM(0), LPARAM(0));
        }
    }
}
