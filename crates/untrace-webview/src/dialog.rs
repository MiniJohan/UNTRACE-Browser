//! Native Windows dialogs and shell actions: the download manager, exports and imports.

use std::path::{Path, PathBuf};

use windows::{
    Win32::{
        Foundation::HWND,
        System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, CoTaskMemFree},
        UI::Shell::{
            Common::COMDLG_FILTERSPEC, FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_NOREADONLYRETURN,
            FOS_OVERWRITEPROMPT, FOS_PATHMUSTEXIST, FOS_STRICTFILETYPES, FileOpenDialog, FileSaveDialog,
            IFileOpenDialog, IFileSaveDialog, IShellItem, SHCreateItemFromParsingName, SIGDN_FILESYSPATH,
        },
    },
    core::{HSTRING, PCWSTR},
};

/// Ask the user where to save a download. `None` if they cancel.
pub fn save_as(owner: HWND, suggested: &Path) -> Option<PathBuf> {
    // SAFETY: standard COM use of the Windows file dialog on the UI (STA) thread; the returned
    // path string is freed with CoTaskMemFree.
    unsafe {
        let dlg: IFileSaveDialog = CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER).ok()?;
        let opts = dlg.GetOptions().ok()?;
        dlg.SetOptions(opts | FOS_OVERWRITEPROMPT | FOS_FORCEFILESYSTEM | FOS_NOREADONLYRETURN | FOS_STRICTFILETYPES)
            .ok()?;
        if let Some(name) = suggested.file_name() {
            let _ = dlg.SetFileName(&HSTRING::from(name));
        }
        if let Some(dir) = suggested.parent().filter(|d| d.is_dir())
            && let Ok(item) = SHCreateItemFromParsingName::<_, _, IShellItem>(&HSTRING::from(dir.as_os_str()), None)
        {
            let _ = dlg.SetFolder(&item);
        }
        dlg.Show(Some(owner)).ok()?; // Err when the user cancels
        let item = dlg.GetResult().ok()?;
        let p = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
        let path = p.to_string().ok().map(PathBuf::from);
        CoTaskMemFree(Some(p.0 as *const _));
        path
    }
}

/// Ask the user for one existing file of one type, e.g. ("Bookmarks file", "*.html;*.htm").
/// `None` if they cancel. UNTRACE reads only the file the user picks.
pub fn open_file(owner: HWND, type_name: &str, pattern: &str) -> Option<PathBuf> {
    let (name, spec) = (HSTRING::from(type_name), HSTRING::from(pattern));
    let types = [COMDLG_FILTERSPEC {
        pszName: PCWSTR(name.as_ptr()),
        pszSpec: PCWSTR(spec.as_ptr()),
    }];
    // SAFETY: standard COM use of the Windows file dialog on the UI (STA) thread; the filter
    // strings outlive the dialog; the returned path string is freed with CoTaskMemFree.
    unsafe {
        let dlg: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;
        let opts = dlg.GetOptions().ok()?;
        dlg.SetOptions(opts | FOS_FORCEFILESYSTEM | FOS_FILEMUSTEXIST | FOS_PATHMUSTEXIST)
            .ok()?;
        let _ = dlg.SetFileTypes(&types);
        dlg.Show(Some(owner)).ok()?; // Err when the user cancels
        let item = dlg.GetResult().ok()?;
        let p = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
        let path = p.to_string().ok().map(PathBuf::from);
        CoTaskMemFree(Some(p.0 as *const _));
        path
    }
}

/// Open Explorer with the file selected. The path is one UNTRACE chose via `save_as`.
pub fn show_in_folder(path: &Path) -> std::io::Result<()> {
    std::process::Command::new("explorer.exe")
        .arg(format!("/select,{}", path.display()))
        .spawn()
        .map(|_| ())
}
