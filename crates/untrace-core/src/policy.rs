//! Browser-security policy decisions (M2). Pure functions, no I/O, no engine types — the content
//! host asks, this module answers, and the answers are unit-tested here.
//!
//! - [`navigation`]: HTTPS-only upgrades and the scheme gate for top-level navigations.
//! - [`external_scheme`]: whether a page may even *ask* to open another application.
//! - [`permission`]: which permission requests are asked about and which are refused outright.
//! - [`download_risk`]: files that can run code when opened.

use std::{collections::BTreeSet, net::IpAddr};

use serde::{Deserialize, Serialize};
use url::{Host, Url};

// ------------------------------------------------------------------ navigation

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    /// `file:` — pages must not read the local disk through navigation.
    LocalFile,
    /// `edge:`, `chrome:`, `view-source:`, `devtools:` — engine-internal pages.
    InternalPage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NavDecision {
    Allow,
    /// Load this `https://` URL instead.
    Upgrade(String),
    Block(BlockReason),
}

/// HTTPS-only state: on/off plus hosts the user allowed over HTTP for this session.
#[derive(Debug, Default, Clone)]
pub struct HttpsOnly {
    pub enabled: bool,
    pub session_exceptions: BTreeSet<String>,
}

/// Loopback hosts never leave the machine, so plain HTTP to them is not upgraded.
pub fn is_loopback(u: &Url) -> bool {
    match u.host() {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost") || d.to_ascii_lowercase().ends_with(".localhost"),
        Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => false,
    }
}

/// Decide a top-level navigation.
pub fn navigation(url: &str, https: &HttpsOnly) -> NavDecision {
    let Ok(u) = Url::parse(url) else {
        return NavDecision::Allow; // the engine rejects what it cannot parse
    };
    match u.scheme() {
        "file" => NavDecision::Block(BlockReason::LocalFile),
        "edge" | "chrome" | "view-source" | "devtools" | "edge-devtools" | "chrome-devtools" => {
            NavDecision::Block(BlockReason::InternalPage)
        }
        "http" => {
            let host = u.host_str().unwrap_or("").to_ascii_lowercase();
            if !https.enabled || is_loopback(&u) || https.session_exceptions.contains(&host) {
                return NavDecision::Allow;
            }
            let mut up = u.clone();
            if up.set_scheme("https").is_err() {
                return NavDecision::Allow;
            }
            if u.port() == Some(80) {
                let _ = up.set_port(None);
            }
            NavDecision::Upgrade(up.to_string())
        }
        // https, about, data, blob and anything else: the engine's own rules apply
        // (external application schemes are decided by `external_scheme`).
        _ => NavDecision::Allow,
    }
}

/// The `http://` URL to fall back to when the user chooses to continue without HTTPS.
pub fn http_fallback(https_url: &str) -> Option<String> {
    let mut u = Url::parse(https_url).ok()?;
    if u.scheme() != "https" {
        return None;
    }
    u.set_scheme("http").ok()?;
    if u.port() == Some(443) {
        let _ = u.set_port(None);
    }
    Some(u.to_string())
}

// ------------------------------------------------------ external applications

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalDecision {
    /// Ask the user, every time.
    Prompt,
    /// Never offered; the reason is shown in the site panel.
    Deny(&'static str),
}

/// Schemes refused without asking, each with the reason it is dangerous.
const DENIED_SCHEMES: &[(&str, &str)] = &[
    (
        "ms-msdt",
        "runs Windows troubleshooters and has been abused to run code (CVE-2022-30190)",
    ),
    (
        "search-ms",
        "opens remote file searches in Explorer and is used to deliver malware",
    ),
    (
        "search",
        "opens remote file searches in Explorer and is used to deliver malware",
    ),
    (
        "ms-search",
        "opens remote file searches in Explorer and is used to deliver malware",
    ),
    (
        "ms-appinstaller",
        "installs apps straight from the web; Microsoft disabled it after abuse",
    ),
    ("ms-officecmd", "has been abused to run code on the computer"),
    ("ms-settings", "changes Windows settings"),
    ("ms-cxh", "opens Windows account set-up flows"),
    ("ms-cxh-full", "opens Windows account set-up flows"),
    ("hcp", "Help Center links have been used to run code"),
    ("its", "opens compiled help files, which can run code"),
    ("ms-its", "opens compiled help files, which can run code"),
    ("mk", "opens compiled help files, which can run code"),
    ("file", "opens files on this computer"),
    ("shell", "opens Explorer locations and programs"),
    ("vbscript", "runs scripts"),
    ("javascript", "runs scripts"),
];

pub fn scheme_of(uri: &str) -> String {
    uri.split(':').next().unwrap_or("").trim().to_ascii_lowercase()
}

/// Decide whether a page may ask to open another application.
pub fn external_scheme(uri: &str, user_initiated: bool) -> ExternalDecision {
    let scheme = scheme_of(uri);
    if let Some((_, why)) = DENIED_SCHEMES.iter().find(|(s, _)| *s == scheme) {
        return ExternalDecision::Deny(why);
    }
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return ExternalDecision::Deny("the address is malformed");
    }
    if !user_initiated {
        return ExternalDecision::Deny("pages may only ask after you click something");
    }
    ExternalDecision::Prompt
}

// ---------------------------------------------------------------- permissions

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Microphone,
    Camera,
    Geolocation,
    Notifications,
    OtherSensors,
    ClipboardRead,
    MultipleAutomaticDownloads,
    FileReadWrite,
    Autoplay,
    LocalFonts,
    MidiSysex,
    WindowManagement,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionPolicy {
    Ask,
    Deny,
}

impl Permission {
    /// Phrase used in "<site> wants to …".
    pub fn ask_phrase(self) -> &'static str {
        match self {
            Self::Microphone => "use your microphone",
            Self::Camera => "use your camera",
            Self::Geolocation => "know your location",
            Self::Notifications => "show notifications",
            Self::OtherSensors => "use motion sensors",
            Self::ClipboardRead => "read your clipboard",
            Self::MultipleAutomaticDownloads => "download several files",
            Self::FileReadWrite => "read and change files you choose",
            Self::Autoplay => "play media with sound automatically",
            Self::LocalFonts => "see the fonts installed on this computer",
            Self::MidiSysex => "fully control MIDI devices",
            Self::WindowManagement => "manage windows on your screens",
            Self::Unknown => "use a browser feature",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Microphone => "Microphone",
            Self::Camera => "Camera",
            Self::Geolocation => "Location",
            Self::Notifications => "Notifications",
            Self::OtherSensors => "Motion sensors",
            Self::ClipboardRead => "Clipboard",
            Self::MultipleAutomaticDownloads => "Multiple downloads",
            Self::FileReadWrite => "Files",
            Self::Autoplay => "Autoplay",
            Self::LocalFonts => "Local fonts",
            Self::MidiSysex => "MIDI devices",
            Self::WindowManagement => "Window management",
            Self::Unknown => "Other",
        }
    }
}

/// Requests that are useful to legitimate sites are asked about; requests mainly useful for
/// fingerprinting or rarely needed are refused without asking.
pub fn permission(p: Permission) -> PermissionPolicy {
    match p {
        Permission::Microphone
        | Permission::Camera
        | Permission::Geolocation
        | Permission::Notifications
        | Permission::ClipboardRead
        | Permission::FileReadWrite
        | Permission::MultipleAutomaticDownloads => PermissionPolicy::Ask,
        Permission::OtherSensors
        | Permission::Autoplay
        | Permission::LocalFonts
        | Permission::MidiSysex
        | Permission::WindowManagement
        | Permission::Unknown => PermissionPolicy::Deny,
    }
}

// ------------------------------------------------------------------ downloads

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadRisk {
    Normal,
    /// Opening the file can run code (programs, scripts, installers, disk images, macro documents).
    RunsCode,
}

const RISKY_EXTENSIONS: &[&str] = &[
    "exe",
    "msi",
    "msp",
    "msix",
    "msixbundle",
    "appx",
    "appxbundle",
    "appinstaller",
    "application",
    "bat",
    "cmd",
    "com",
    "cpl",
    "scr",
    "pif",
    "ps1",
    "psm1",
    "psd1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
    "hta",
    "lnk",
    "url",
    "reg",
    "dll",
    "sys",
    "jar",
    "iso",
    "img",
    "vhd",
    "vhdx",
    "msc",
    "inf",
    "scf",
    "chm",
    "gadget",
    "settingcontent-ms",
    "docm",
    "dotm",
    "xlsm",
    "xltm",
    "xlam",
    "pptm",
    "potm",
    "ppam",
    "sldm",
];

pub fn download_risk(file_name: &str) -> DownloadRisk {
    let name = file_name.trim().trim_end_matches(['.', ' ']).to_ascii_lowercase();
    match name.rsplit_once('.') {
        Some((_, ext)) if RISKY_EXTENSIONS.contains(&ext) => DownloadRisk::RunsCode,
        _ => DownloadRisk::Normal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on() -> HttpsOnly {
        HttpsOnly {
            enabled: true,
            session_exceptions: BTreeSet::new(),
        }
    }

    #[test]
    fn https_only_upgrades_plain_http() {
        assert_eq!(
            navigation("http://example.com/a?b=1#c", &on()),
            NavDecision::Upgrade("https://example.com/a?b=1#c".into())
        );
        assert_eq!(
            navigation("http://example.com:80/", &on()),
            NavDecision::Upgrade("https://example.com/".into())
        );
        assert_eq!(
            navigation("http://example.com:8080/", &on()),
            NavDecision::Upgrade("https://example.com:8080/".into())
        );
        assert_eq!(
            navigation("http://192.168.1.1/", &on()),
            NavDecision::Upgrade("https://192.168.1.1/".into())
        );
    }

    #[test]
    fn https_only_leaves_other_cases_alone() {
        assert_eq!(navigation("https://example.com/", &on()), NavDecision::Allow);
        for local in [
            "http://localhost:3000/",
            "http://app.localhost/",
            "http://127.0.0.1:8080/",
            "http://[::1]/",
        ] {
            assert_eq!(navigation(local, &on()), NavDecision::Allow, "{local}");
        }
        let off = HttpsOnly::default();
        assert_eq!(navigation("http://example.com/", &off), NavDecision::Allow);
        let mut ex = on();
        ex.session_exceptions.insert("example.com".into());
        assert_eq!(navigation("http://EXAMPLE.com/x", &ex), NavDecision::Allow);
        assert_eq!(
            navigation("http://other.example.com/x", &ex),
            NavDecision::Upgrade("https://other.example.com/x".into())
        );
    }

    #[test]
    fn scheme_gate_blocks_local_and_internal_pages() {
        assert_eq!(
            navigation("file:///C:/Users/x/secret.txt", &on()),
            NavDecision::Block(BlockReason::LocalFile)
        );
        for s in [
            "edge://settings",
            "chrome://gpu",
            "view-source:https://a.com",
            "devtools://devtools/x",
        ] {
            assert_eq!(
                navigation(s, &on()),
                NavDecision::Block(BlockReason::InternalPage),
                "{s}"
            );
        }
        assert_eq!(navigation("about:blank", &on()), NavDecision::Allow);
    }

    #[test]
    fn http_fallback_reverses_the_upgrade() {
        assert_eq!(
            http_fallback("https://example.com/a?b").as_deref(),
            Some("http://example.com/a?b")
        );
        assert_eq!(
            http_fallback("https://example.com:443/").as_deref(),
            Some("http://example.com/")
        );
        assert_eq!(http_fallback("http://example.com/"), None);
    }

    #[test]
    fn external_schemes() {
        assert_eq!(external_scheme("mailto:a@b.c", true), ExternalDecision::Prompt);
        assert_eq!(
            external_scheme("zoommtg://zoom.us/join", true),
            ExternalDecision::Prompt
        );
        assert!(matches!(
            external_scheme("mailto:a@b.c", false),
            ExternalDecision::Deny(_)
        ));
        for s in [
            "ms-msdt:/id PCWDiagnostic",
            "SEARCH-MS:query=x",
            "ms-settings:privacy",
            "ms-appinstaller:?source=x",
            "file:///c:/",
        ] {
            assert!(matches!(external_scheme(s, true), ExternalDecision::Deny(_)), "{s}");
        }
        assert!(matches!(
            external_scheme("bad scheme:x", true),
            ExternalDecision::Deny(_)
        ));
    }

    #[test]
    fn permissions_ask_or_deny() {
        assert_eq!(permission(Permission::Camera), PermissionPolicy::Ask);
        assert_eq!(permission(Permission::Notifications), PermissionPolicy::Ask);
        assert_eq!(permission(Permission::LocalFonts), PermissionPolicy::Deny);
        assert_eq!(permission(Permission::OtherSensors), PermissionPolicy::Deny);
        assert_eq!(permission(Permission::Unknown), PermissionPolicy::Deny);
    }

    #[test]
    fn download_risk_by_extension() {
        for f in [
            "setup.exe",
            "INSTALL.MSI",
            "run.ps1",
            "invoice.pdf.exe",
            "image.iso",
            "report.xlsm",
            "trailing.exe. ",
        ] {
            assert_eq!(download_risk(f), DownloadRisk::RunsCode, "{f}");
        }
        for f in [
            "report.pdf",
            "photo.jpg",
            "notes.txt",
            "archive.zip",
            "noextension",
            "data.xlsx",
        ] {
            assert_eq!(download_risk(f), DownloadRisk::Normal, "{f}");
        }
    }
}
