//! D-053: UNTRACE's look (theme and accent colour) and the light/dark preference web pages
//! are told. UNTRACE's own look is not visible to websites; the page preference is
//! (`prefers-color-scheme`), as in every browser.

use std::ffi::c_void;

use tauri::{AppHandle, Manager};
use untrace_core::settings::Theme;
use untrace_webview::{ContentHost, PageColorScheme};
use windows::Win32::Foundation::COLORREF;
use windows::Win32::Graphics::Dwm::{
    DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute,
};
use windows::core::BOOL;

use crate::AppState;

/// The window frame (Windows' own title bar) in the theme's colours: the colour of UNTRACE's
/// top bar (`--chrome` in tokens.css) and the theme's text colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub dark: bool,
    pub caption: [u8; 3],
    pub text: [u8; 3],
}

const DARK_TEXT: [u8; 3] = [0xed, 0xed, 0xef];
const LIGHT_TEXT: [u8; 3] = [0x16, 0x16, 0x18];

pub fn frame(theme: Theme, windows_dark: bool) -> Frame {
    match theme {
        Theme::Black => Frame {
            dark: true,
            caption: [0x06, 0x06, 0x07],
            text: DARK_TEXT,
        },
        Theme::Dark => Frame {
            dark: true,
            caption: [0x14, 0x14, 0x15],
            text: DARK_TEXT,
        },
        Theme::Light => Frame {
            dark: false,
            caption: [0xf4, 0xf4, 0xf5],
            text: LIGHT_TEXT,
        },
        Theme::System => frame(if windows_dark { Theme::Dark } else { Theme::Light }, windows_dark),
    }
}

/// Is Windows set to dark mode for apps (what "System" follows)?
pub fn windows_dark(app: &AppHandle) -> bool {
    app.get_webview_window("main")
        .and_then(|w| w.theme().ok())
        .map(|t| t == tauri::Theme::Dark)
        .unwrap_or(true)
}

/// Colour the window's title bar to match the theme. Windows 11 honours the caption and text
/// colours; Windows 10 keeps its own and only takes the light/dark choice. Visual only.
pub fn apply_frame(app: &AppHandle) {
    let Some(w) = app.get_webview_window("main") else {
        return;
    };
    let Ok(hwnd) = w.hwnd() else {
        return;
    };
    let theme = app.state::<AppState>().store.lock().unwrap().settings().theme;
    let f = frame(theme, windows_dark(app));
    let rgb = |c: [u8; 3]| COLORREF(c[0] as u32 | (c[1] as u32) << 8 | (c[2] as u32) << 16);
    let dark = BOOL::from(f.dark);
    let (caption, text) = (rgb(f.caption), rgb(f.text));
    // SAFETY: our own top-level window; each value is a BOOL or COLORREF of the size passed.
    unsafe {
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &dark as *const BOOL as *const c_void,
            size_of::<BOOL>() as u32,
        );
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_CAPTION_COLOR,
            &caption as *const COLORREF as *const c_void,
            size_of::<COLORREF>() as u32,
        );
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_TEXT_COLOR,
            &text as *const COLORREF as *const c_void,
            size_of::<COLORREF>() as u32,
        );
    }
}

/// Windows switched between light and dark: "System" follows it in the frame and in the
/// background pages show before they paint.
pub fn windows_theme_changed(app: &AppHandle) {
    apply_frame(app);
    if let Some(h) = crate::host() {
        let _ = apply(app, &h);
    }
}

/// What pages are told: UNTRACE's light/dark choice when "Websites follow this theme" is on;
/// otherwise, and for "System", whatever Windows uses.
pub fn page_scheme(theme: Theme, follow: bool) -> PageColorScheme {
    if !follow {
        return PageColorScheme::Auto;
    }
    match theme {
        Theme::System => PageColorScheme::Auto,
        Theme::Light => PageColorScheme::Light,
        Theme::Dark | Theme::Black => PageColorScheme::Dark,
    }
}

/// Apply the saved look to the running engine: the background pages show before they paint,
/// and the colour scheme they are told.
pub fn apply(app: &AppHandle, host: &ContentHost) -> Result<(), String> {
    let state = app.state::<AppState>();
    let (theme, follow) = {
        let store = state.store.lock().unwrap();
        (store.settings().theme, store.settings().pages_follow_theme)
    };
    host.set_background(crate::content_background(app, theme));
    host.set_page_color_scheme(page_scheme(theme, follow))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_follow_the_theme_only_when_asked() {
        assert_eq!(page_scheme(Theme::Dark, true), PageColorScheme::Dark);
        assert_eq!(page_scheme(Theme::Black, true), PageColorScheme::Dark);
        assert_eq!(page_scheme(Theme::Light, true), PageColorScheme::Light);
        assert_eq!(page_scheme(Theme::System, true), PageColorScheme::Auto);
        for t in [Theme::System, Theme::Dark, Theme::Black, Theme::Light] {
            assert_eq!(page_scheme(t, false), PageColorScheme::Auto);
        }
    }

    /// The title bar takes each theme's `--chrome` and `--text` from tokens.css; this fails if
    /// the two drift apart.
    #[test]
    fn the_frame_matches_the_top_bar_of_each_theme() {
        let tokens = include_str!("../../ui/src/styles/tokens.css");
        let block = |selector: &str| {
            let start = tokens.find(selector).expect("theme block in tokens.css");
            &tokens[start..start + tokens[start..].find('}').unwrap()]
        };
        let token = |block: &str, name: &str| -> [u8; 3] {
            let at = block
                .find(&format!("{name}: #"))
                .unwrap_or_else(|| panic!("{name} in block"))
                + name.len()
                + 3;
            let hex = &block[at..at + 6];
            [0, 2, 4].map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        };
        let dark = block(":root {");
        let black = block(r#":root[data-theme="black"] {"#);
        let light = block(r#":root[data-theme="light"] {"#);
        assert_eq!(frame(Theme::Dark, true).caption, token(dark, "--chrome"));
        assert_eq!(frame(Theme::Black, true).caption, token(black, "--chrome"));
        assert_eq!(frame(Theme::Light, true).caption, token(light, "--chrome"));
        assert_eq!(frame(Theme::Dark, true).text, token(dark, "--text"));
        assert_eq!(frame(Theme::Light, true).text, token(light, "--text"));
        assert!(frame(Theme::Black, false).dark && !frame(Theme::Light, true).dark);
        assert_eq!(frame(Theme::System, true), frame(Theme::Dark, true));
        assert_eq!(frame(Theme::System, false), frame(Theme::Light, false));
    }
}
