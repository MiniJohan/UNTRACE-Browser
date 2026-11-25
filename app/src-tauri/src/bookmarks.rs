//! D-055: bookmarks. They live only in `config/bookmarks.json`; UNTRACE never fetches anything
//! for them (a bookmark's icon is the one its page showed when it was added). Import reads only
//! the file the user picks; the activity log records counts, never addresses or titles.

use std::path::Path;

use serde::Serialize;
use tauri::{AppHandle, State};
use untrace_core::{
    audit::{AuditEvent, AuditLog},
    bookmarks::{self, BookmarkStore, ImportReport, Item},
    store::LoadOutcome,
};

use crate::{
    AppState,
    commands::{R, on_ui_thread, owner, today},
    host,
};

/// Open the bookmarks at start. A failure is logged and reported by every bookmark command;
/// the browser itself works without them.
pub fn open(config: &Path, audit: &AuditLog) -> Result<BookmarkStore, String> {
    match BookmarkStore::open(config) {
        Ok((store, outcome)) => {
            let note = match &outcome {
                LoadOutcome::Repaired { repairs } => Some(format!("repaired: {}", repairs.join("; "))),
                LoadOutcome::Reset { reason, .. } => {
                    Some(format!("unreadable file set aside, starting empty: {reason}"))
                }
                LoadOutcome::Created | LoadOutcome::Loaded => None,
            };
            if let Some(outcome) = note {
                let _ = audit.record(AuditEvent::BookmarksLoaded { outcome });
            }
            Ok(store)
        }
        Err(e) => {
            let message = format!("The bookmarks could not be opened ({e}).");
            let _ = audit.record(AuditEvent::Error {
                component: "bookmarks".into(),
                message: message.clone(),
            });
            Err(message)
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BookmarksView {
    items: Vec<Item>,
    count: usize,
    max: usize,
}

fn view(s: &BookmarkStore) -> BookmarksView {
    BookmarksView {
        items: s.data().items.clone(),
        count: s.data().bookmark_count(),
        max: bookmarks::MAX_BOOKMARKS,
    }
}

fn with_store<T>(state: &AppState, f: impl FnOnce(&mut BookmarkStore) -> R<T>) -> R<T> {
    match state.bookmarks.lock().unwrap().as_mut() {
        Ok(s) => f(s),
        Err(e) => Err(e.clone()),
    }
}

#[tauri::command]
pub fn bookmarks_get(state: State<AppState>) -> R<BookmarksView> {
    on_ui_thread(&state)?;
    with_store(&state, |s| Ok(view(s)))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Added {
    id: u64,
    /// False when the address was already bookmarked (it is not added twice).
    created: bool,
    view: BookmarksView,
}

/// Bookmark the page a tab shows, with its title and the icon it showed. Address, title and
/// icon come from the engine's own record of the tab, not from the interface.
#[tauri::command]
pub fn bookmark_add_tab(state: State<AppState>, tab_id: u32) -> R<Added> {
    on_ui_thread(&state)?;
    let h = host().ok_or("The browser engine is not running.")?;
    let tab = h
        .snapshot()
        .tabs
        .into_iter()
        .find(|t| t.id == tab_id)
        .ok_or("That tab is closed.")?;
    if tab.interstitial.is_some() {
        return Err("UNTRACE stopped this page, so it cannot be bookmarked.".into());
    }
    with_store(&state, |s| {
        if let Some(id) = s.data().find_url(&tab.url) {
            return Ok(Added {
                id,
                created: false,
                view: view(s),
            });
        }
        let id = s.change(|f, now| f.add(&tab.title, &tab.url, tab.favicon.as_deref(), None, now))?;
        Ok(Added {
            id,
            created: true,
            view: view(s),
        })
    })
}

/// Rename a bookmark or folder; for a bookmark, `url` changes its address.
#[tauri::command]
pub fn bookmark_edit(state: State<AppState>, id: u64, title: String, url: Option<String>) -> R<BookmarksView> {
    on_ui_thread(&state)?;
    with_store(&state, |s| {
        s.change(|f, _| f.edit(id, &title, url.as_deref()))?;
        Ok(view(s))
    })
}

/// Remove a bookmark, or a folder with the bookmarks in it.
#[tauri::command]
pub fn bookmark_remove(state: State<AppState>, id: u64) -> R<BookmarksView> {
    on_ui_thread(&state)?;
    with_store(&state, |s| {
        s.change(|f, _| f.remove(id))?;
        Ok(view(s))
    })
}

#[tauri::command]
pub fn bookmark_folder_add(state: State<AppState>, title: String) -> R<Added> {
    on_ui_thread(&state)?;
    with_store(&state, |s| {
        let id = s.change(|f, now| f.add_folder(&title, now))?;
        Ok(Added {
            id,
            created: true,
            view: view(s),
        })
    })
}

/// Put a bookmark or folder at `index` of the top level or of a folder.
#[tauri::command]
pub fn bookmark_move(state: State<AppState>, id: u64, folder: Option<u64>, index: usize) -> R<BookmarksView> {
    on_ui_thread(&state)?;
    with_store(&state, |s| {
        s.change(|f, _| f.move_to(id, folder, index))?;
        Ok(view(s))
    })
}

#[tauri::command]
pub fn bookmarks_delete_all(state: State<AppState>) -> R<BookmarksView> {
    on_ui_thread(&state)?;
    let (count, out) = with_store(&state, |s| {
        let count = s.data().bookmark_count();
        s.change(|f, _| {
            f.items.clear();
            Ok(())
        })?;
        Ok((count, view(s)))
    })?;
    let _ = state.audit.record(AuditEvent::BookmarksDeleted { count });
    Ok(out)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Imported {
    report: ImportReport,
    view: BookmarksView,
}

/// Import a bookmarks file the user picks (exported as HTML by Chrome, Edge, Firefox or
/// UNTRACE). `None` if they cancelled.
#[tauri::command]
pub fn bookmarks_import(app: AppHandle, state: State<AppState>) -> R<Option<Imported>> {
    on_ui_thread(&state)?;
    with_store(&state, |_| Ok(()))?;
    let Some(path) = untrace_webview::open_file(owner(&app), "Bookmarks file (HTML)", "*.html;*.htm") else {
        return Ok(None);
    };
    let len = std::fs::metadata(&path)
        .map_err(|e| format!("The file could not be read ({e})."))?
        .len();
    if len > bookmarks::MAX_FILE_BYTES {
        return Err("This file is too large to be a bookmarks file.".into());
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("The file could not be read ({e})."))?;
    let links = bookmarks::parse_html(&String::from_utf8_lossy(&bytes));
    if links.is_empty() {
        return Err("No bookmarks were found in this file. Choose a bookmarks file exported as HTML.".into());
    }
    let out = with_store(&state, |s| {
        let report = s.change(|f, now| Ok(f.import(links, now)))?;
        Ok(Imported { report, view: view(s) })
    })?;
    let r = &out.report;
    let _ = state.audit.record(AuditEvent::BookmarksImported {
        added: r.added,
        skipped: r.duplicates + r.unsupported + r.over_limit,
    });
    Ok(Some(out))
}

/// Save the bookmarks as a standard bookmarks file where the user chooses. Returns the file's
/// path, or `None` if they cancelled.
#[tauri::command]
pub fn bookmarks_export(app: AppHandle, state: State<AppState>) -> R<Option<String>> {
    on_ui_thread(&state)?;
    let (html, count) = with_store(&state, |s| Ok((s.data().export_html(), s.data().bookmark_count())))?;
    let Some(path) = untrace_webview::save_as(owner(&app), Path::new(&format!("untrace-bookmarks-{}.html", today())))
    else {
        return Ok(None);
    };
    std::fs::write(&path, html).map_err(|e| format!("The file could not be written ({e})."))?;
    let _ = state.audit.record(AuditEvent::BookmarksExported { count });
    Ok(Some(path.display().to_string()))
}
