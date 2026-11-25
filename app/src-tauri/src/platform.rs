//! Windows specifics for the shell: elevation check and a last-resort message box.

use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
        UI::WindowsAndMessaging::{MB_ICONWARNING, MB_OK, MessageBoxW},
    },
    core::HSTRING,
};

/// True when UNTRACE runs with an elevated (administrator) token.
pub fn is_elevated() -> bool {
    // SAFETY: querying our own process token into a correctly sized struct; the handle is closed.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut e = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut e as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && e.TokenIsElevated != 0
    }
}

pub fn message_box(title: &str, text: &str) {
    // SAFETY: modal message box with owned strings.
    unsafe {
        MessageBoxW(
            None,
            &HSTRING::from(text),
            &HSTRING::from(title),
            MB_OK | MB_ICONWARNING,
        );
    }
}
