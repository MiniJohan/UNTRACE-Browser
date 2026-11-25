<!-- Draft for the wry / Tauri issue tracker. Not posted. Review before use. -->

# Windows: allow enabling WebView2 custom crash reporting (`IsCustomCrashReportingEnabled`)

## Problem

On Windows, wry creates the WebView2 environment with `CoreWebView2EnvironmentOptions` in `webview2/mod.rs` (`create_environment`). It sets the additional browser arguments, browser extensions, language and scroll-bar style, but never `IsCustomCrashReportingEnabled`.

That option stays at its default (`false`), so WebView2 crash dumps are handled by Windows Error Reporting and may be sent to Microsoft. Microsoft documents this option as the way for apps to keep crash dumps local ([Data and privacy in WebView2](https://learn.microsoft.com/microsoft-edge/webview2/concepts/data-privacy)).

Privacy-sensitive apps that need dumps to stay on the device currently cannot use the environment wry creates. They must create and manage a second WebView2 environment themselves. In our measurements that costs about 120 MB of private memory (5 extra processes).

## Proposal

- **wry:** add a Windows-specific attribute, e.g. `WebViewBuilderExtWindows::with_custom_crash_reporting(bool)`, passed to `options.set_is_custom_crash_reporting_enabled(...)` in `create_environment`. `webview2-com`'s `CoreWebView2EnvironmentOptions` already has the setter.
- **Tauri:** expose it on `WebviewWindowBuilder` / `WebviewBuilder` (Windows only), next to `additional_browser_args` and `browser_extensions_enabled`.

The default stays `false`, so existing behaviour is unchanged.

## Notes

- Like the other environment options, the value must match across webviews sharing a data directory. The existing documentation for `additional_browser_args` already covers this.
- `ICoreWebView2Environment11::FailureReportFolderPath` tells the app where the dumps are written.
