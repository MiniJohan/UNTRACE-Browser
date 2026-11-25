//! Where UNTRACE keeps its data. Everything lives under one per-user, non-roaming folder.

use std::path::PathBuf;

/// Root data folder: `%LOCALAPPDATA%\UNTRACE`.
/// `UNTRACE_DATA_DIR` overrides it (development and tests only; it is shown in Diagnostics).
pub fn data_root() -> PathBuf {
    if let Some(p) = std::env::var_os("UNTRACE_DATA_DIR") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("UNTRACE")
}

/// True when the data root was overridden by `UNTRACE_DATA_DIR`.
pub fn data_root_overridden() -> bool {
    std::env::var_os("UNTRACE_DATA_DIR").is_some()
}

pub struct Layout {
    pub root: PathBuf,
    pub config: PathBuf,
    pub logs: PathBuf,
    pub ui_webview: PathBuf,
    pub content_webview: PathBuf,
}

impl Layout {
    pub fn new(root: PathBuf) -> Self {
        Self {
            config: root.join("config"),
            logs: root.join("logs"),
            ui_webview: root.join("ui"),
            content_webview: root.join("content"),
            root,
        }
    }

    pub fn create_all(&self) -> std::io::Result<()> {
        for d in [
            &self.root,
            &self.config,
            &self.logs,
            &self.ui_webview,
            &self.content_webview,
        ] {
            std::fs::create_dir_all(d)?;
        }
        Ok(())
    }
}
