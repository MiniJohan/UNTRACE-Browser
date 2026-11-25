//! D-053: UNTRACE's look (theme and accent colour) and the light/dark preference web pages
//! are told. UNTRACE's own look is not visible to websites; the page preference is
//! (`prefers-color-scheme`), as in every browser.

use tauri::{AppHandle, Manager};
use untrace_core::settings::Theme;
use untrace_webview::{ContentHost, PageColorScheme};

use crate::AppState;

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
}
