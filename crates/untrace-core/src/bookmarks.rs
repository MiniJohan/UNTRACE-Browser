//! Bookmarks (D-055): kept only on this computer, in `config/bookmarks.json`, validated on load
//! and written atomically. Folders are one level deep. Only web addresses (http and https) are
//! kept: no scripts (`javascript:`), local files or engine pages.
//!
//! Import and export use the bookmarks file every browser reads and writes (the "Netscape"
//! HTML format). An imported file is untrusted input: it is read by the small tolerant parser
//! below, never rendered, and only its addresses, titles and folder names are kept.

use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::store::{LoadOutcome, write_atomic};

pub const MAX_BOOKMARKS: usize = 10_000;
pub const MAX_FOLDERS: usize = 1_000;
/// Characters in a title or folder name.
pub const MAX_TITLE: usize = 300;
/// Bytes in an address.
pub const MAX_URL: usize = 4096;
/// Bytes in a stored site icon (a PNG data URL); larger icons are not kept.
pub const MAX_ICON: usize = 16 * 1024;
/// Bytes of a bookmarks file UNTRACE reads: its own, or one being imported.
pub const MAX_FILE_BYTES: u64 = 192 * 1024 * 1024;
/// Links read from one imported file.
const MAX_IMPORT_LINKS: usize = 100_000;
/// Folder levels kept in an imported folder's name ("A / B / C").
const MAX_IMPORT_DEPTH: usize = 8;
const ICON_PREFIX: &str = "data:image/png;base64,";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bookmark {
    pub id: u64,
    pub title: String,
    pub url: String,
    /// The site's icon as the page showed it when it was bookmarked (never fetched).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    /// When it was added (seconds since 1970).
    #[serde(default)]
    pub added: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Folder {
    pub id: u64,
    pub title: String,
    #[serde(default)]
    pub added: u64,
    #[serde(default)]
    pub items: Vec<Bookmark>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Item {
    Bookmark(Bookmark),
    Folder(Folder),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookmarkFile {
    pub schema: u32,
    pub next_id: u64,
    pub items: Vec<Item>,
}

impl Default for BookmarkFile {
    fn default() -> Self {
        Self {
            schema: 1,
            next_id: 1,
            items: Vec::new(),
        }
    }
}

/// What an import did, in counts (the activity log never records addresses).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub added: usize,
    pub folders_added: usize,
    /// Already bookmarked in the same place.
    pub duplicates: usize,
    /// Not a web address (scripts, files, engine pages) or unreadable.
    pub unsupported: usize,
    /// Over the bookmark or folder limit.
    pub over_limit: usize,
}

/// A link read from an imported file, before it is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedLink {
    /// The folders it sits in, outermost first.
    pub folders: Vec<String>,
    pub title: String,
    pub url: String,
}

/// A web address as UNTRACE keeps it, or why it is not kept.
pub fn normalize_url(input: &str) -> Result<String, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("The address is empty.".into());
    }
    if s.len() > MAX_URL {
        return Err("The address is too long.".into());
    }
    let u = url::Url::parse(s).map_err(|_| "This is not a web address.".to_string())?;
    if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none_or(str::is_empty) {
        return Err("Only web addresses (http or https) can be bookmarked.".into());
    }
    let out = u.to_string();
    if out.len() > MAX_URL {
        return Err("The address is too long.".into());
    }
    Ok(out)
}

/// One line, no control characters, at most [`MAX_TITLE`] characters.
pub fn clean_title(input: &str) -> String {
    let spaced: String = input.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let one_line = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    // Cut, then trim: a cut just after a space must not leave one at the end (found by fuzzing:
    // cleaning such a title again changed it).
    let cut: String = one_line.chars().take(MAX_TITLE).collect();
    cut.trim_end().to_string()
}

/// A bookmark's title: the one given, or else the address's host.
fn bookmark_title(title: &str, url: &str) -> String {
    let t = clean_title(title);
    if !t.is_empty() {
        return t;
    }
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(clean_title))
        .unwrap_or_else(|| clean_title(url))
}

/// A PNG data URL within the size limit, or nothing.
pub fn clean_icon(icon: Option<&str>) -> Option<String> {
    let icon = icon?;
    let data = icon.strip_prefix(ICON_PREFIX)?;
    let ok = icon.len() <= MAX_ICON
        && !data.is_empty()
        && data
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
    ok.then(|| icon.to_string())
}

fn for_each_id(items: &mut [Item], mut f: impl FnMut(&mut u64)) {
    for item in items {
        match item {
            Item::Bookmark(b) => f(&mut b.id),
            Item::Folder(folder) => {
                f(&mut folder.id);
                for b in folder.items.iter_mut() {
                    f(&mut b.id);
                }
            }
        }
    }
}

impl BookmarkFile {
    pub fn bookmark_count(&self) -> usize {
        self.items
            .iter()
            .map(|i| match i {
                Item::Bookmark(_) => 1,
                Item::Folder(f) => f.items.len(),
            })
            .sum()
    }

    pub fn folder_count(&self) -> usize {
        self.items.iter().filter(|i| matches!(i, Item::Folder(_))).count()
    }

    fn folder_mut(&mut self, id: u64) -> Option<&mut Folder> {
        self.items.iter_mut().find_map(|i| match i {
            Item::Folder(f) if f.id == id => Some(f),
            _ => None,
        })
    }

    fn folder_named(&self, title: &str) -> Option<u64> {
        self.items.iter().find_map(|i| match i {
            Item::Folder(f) if f.title == title => Some(f.id),
            _ => None,
        })
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id.max(1);
        self.next_id = id + 1;
        id
    }

    /// The first bookmark of this address, if any.
    pub fn find_url(&self, url: &str) -> Option<u64> {
        let url = normalize_url(url).ok()?;
        self.items.iter().find_map(|i| match i {
            Item::Bookmark(b) if b.url == url => Some(b.id),
            Item::Folder(f) => f.items.iter().find(|b| b.url == url).map(|b| b.id),
            _ => None,
        })
    }

    pub fn add(
        &mut self,
        title: &str,
        url: &str,
        icon: Option<&str>,
        folder: Option<u64>,
        now: u64,
    ) -> Result<u64, String> {
        let url = normalize_url(url)?;
        if self.bookmark_count() >= MAX_BOOKMARKS {
            return Err(format!("UNTRACE keeps at most {MAX_BOOKMARKS} bookmarks."));
        }
        if let Some(fid) = folder
            && self.folder_mut(fid).is_none()
        {
            return Err("That folder no longer exists.".into());
        }
        let id = self.take_id();
        let b = Bookmark {
            id,
            title: bookmark_title(title, &url),
            url,
            icon: clean_icon(icon),
            added: now,
        };
        match folder.and_then(|fid| self.folder_mut(fid)) {
            Some(f) => f.items.push(b),
            None => self.items.push(Item::Bookmark(b)),
        }
        Ok(id)
    }

    pub fn add_folder(&mut self, title: &str, now: u64) -> Result<u64, String> {
        let title = clean_title(title);
        if title.is_empty() {
            return Err("Give the folder a name.".into());
        }
        if self.folder_count() >= MAX_FOLDERS {
            return Err(format!("UNTRACE keeps at most {MAX_FOLDERS} folders."));
        }
        let id = self.take_id();
        self.items.push(Item::Folder(Folder {
            id,
            title,
            added: now,
            items: Vec::new(),
        }));
        Ok(id)
    }

    /// Rename a bookmark or folder; a bookmark's address changes too when one is given.
    pub fn edit(&mut self, id: u64, title: &str, url: Option<&str>) -> Result<(), String> {
        let new_url = url.map(normalize_url).transpose()?;
        for item in self.items.iter_mut() {
            match item {
                Item::Folder(f) if f.id == id => {
                    let t = clean_title(title);
                    if t.is_empty() {
                        return Err("Give the folder a name.".into());
                    }
                    f.title = t;
                    return Ok(());
                }
                Item::Bookmark(b) if b.id == id => {
                    edit_bookmark(b, title, new_url);
                    return Ok(());
                }
                Item::Folder(f) => {
                    if let Some(b) = f.items.iter_mut().find(|b| b.id == id) {
                        edit_bookmark(b, title, new_url);
                        return Ok(());
                    }
                }
                Item::Bookmark(_) => {}
            }
        }
        Err("That bookmark no longer exists.".into())
    }

    /// Remove a bookmark, or a folder with everything in it.
    pub fn remove(&mut self, id: u64) -> Result<(), String> {
        self.take(id)
            .map(|_| ())
            .ok_or_else(|| "That bookmark no longer exists.".into())
    }

    fn take(&mut self, id: u64) -> Option<Item> {
        if let Some(pos) = self.items.iter().position(|i| match i {
            Item::Bookmark(b) => b.id == id,
            Item::Folder(f) => f.id == id,
        }) {
            return Some(self.items.remove(pos));
        }
        self.items.iter_mut().find_map(|i| match i {
            Item::Folder(f) => f
                .items
                .iter()
                .position(|b| b.id == id)
                .map(|pos| Item::Bookmark(f.items.remove(pos))),
            Item::Bookmark(_) => None,
        })
    }

    /// Put a bookmark or folder at `index` of the top level (`folder` None) or of a folder.
    /// The index counts positions after the item has been taken out of its old place.
    pub fn move_to(&mut self, id: u64, folder: Option<u64>, index: usize) -> Result<(), String> {
        // Everything is checked before the item leaves its place.
        if let Some(fid) = folder {
            if self.items.iter().any(|i| matches!(i, Item::Folder(f) if f.id == id)) {
                return Err("Folders cannot go inside other folders.".into());
            }
            if self.folder_mut(fid).is_none() {
                return Err("That folder no longer exists.".into());
            }
        }
        let item = self.take(id).ok_or("That bookmark no longer exists.")?;
        match (item, folder.and_then(|fid| self.folder_mut(fid))) {
            (Item::Bookmark(b), Some(f)) => {
                let at = index.min(f.items.len());
                f.items.insert(at, b);
            }
            (item, _) => {
                let at = index.min(self.items.len());
                self.items.insert(at, item);
            }
        }
        Ok(())
    }

    /// Add the links of an imported file: folders become one-level folders named by their path
    /// ("Bookmarks bar / Work"); what is already bookmarked in the same place is skipped.
    pub fn import(&mut self, links: Vec<ImportedLink>, now: u64) -> ImportReport {
        let mut r = ImportReport::default();
        let mut count = self.bookmark_count();
        let mut present: HashSet<(Option<u64>, String)> = HashSet::new();
        for item in &self.items {
            match item {
                Item::Bookmark(b) => {
                    present.insert((None, b.url.clone()));
                }
                Item::Folder(f) => {
                    for b in &f.items {
                        present.insert((Some(f.id), b.url.clone()));
                    }
                }
            }
        }
        for link in links {
            let Ok(url) = normalize_url(&link.url) else {
                r.unsupported += 1;
                continue;
            };
            let name = clean_title(&link.folders.join(" / "));
            let target = if name.is_empty() {
                None
            } else if let Some(id) = self.folder_named(&name) {
                Some(id)
            } else if self.folder_count() >= MAX_FOLDERS {
                r.over_limit += 1;
                continue;
            } else {
                r.folders_added += 1;
                Some(self.add_folder(&name, now).expect("checked name and limit"))
            };
            if !present.insert((target, url.clone())) {
                r.duplicates += 1;
                continue;
            }
            if count >= MAX_BOOKMARKS {
                r.over_limit += 1;
                continue;
            }
            let id = self.take_id();
            let b = Bookmark {
                id,
                title: bookmark_title(&link.title, &url),
                url,
                icon: None,
                added: now,
            };
            match target.and_then(|fid| self.folder_mut(fid)) {
                Some(f) => f.items.push(b),
                None => self.items.push(Item::Bookmark(b)),
            }
            count += 1;
            r.added += 1;
        }
        r
    }

    /// The bookmarks as a standard bookmarks file that other browsers import.
    pub fn export_html(&self) -> String {
        let mut s = String::from(
            "<!DOCTYPE NETSCAPE-Bookmark-file-1>\n<!-- Exported by UNTRACE. -->\n\
             <META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">\n\
             <TITLE>Bookmarks</TITLE>\n<H1>Bookmarks</H1>\n<DL><p>\n",
        );
        let link = |s: &mut String, b: &Bookmark, indent: &str| {
            let icon = b
                .icon
                .as_deref()
                .map(|i| format!(" ICON=\"{}\"", escape(i)))
                .unwrap_or_default();
            s.push_str(&format!(
                "{indent}<DT><A HREF=\"{}\" ADD_DATE=\"{}\"{icon}>{}</A>\n",
                escape(&b.url),
                b.added,
                escape(&b.title)
            ));
        };
        for item in &self.items {
            match item {
                Item::Bookmark(b) => link(&mut s, b, "    "),
                Item::Folder(f) => {
                    s.push_str(&format!(
                        "    <DT><H3 ADD_DATE=\"{}\">{}</H3>\n    <DL><p>\n",
                        f.added,
                        escape(&f.title)
                    ));
                    for b in &f.items {
                        link(&mut s, b, "        ");
                    }
                    s.push_str("    </DL><p>\n");
                }
            }
        }
        s.push_str("</DL><p>\n");
        s
    }

    /// Check and repair what was read from disk: drop entries UNTRACE would never have
    /// written, keep the limits, give missing or duplicate ids new ones. Returns the repairs.
    pub fn validate(&mut self) -> Vec<String> {
        let mut repairs = Vec::new();
        if self.schema != 1 {
            repairs.push(format!("unknown schema {}, read as schema 1", self.schema));
            self.schema = 1;
        }
        let mut dropped = 0usize;
        let mut kept = 0usize;
        let mut folders = 0usize;
        let keep = |b: &mut Bookmark, kept: &mut usize| -> bool {
            let Ok(url) = normalize_url(&b.url) else {
                return false;
            };
            if *kept >= MAX_BOOKMARKS {
                return false;
            }
            b.title = bookmark_title(&b.title, &url);
            b.url = url;
            b.icon = clean_icon(b.icon.as_deref());
            *kept += 1;
            true
        };
        let mut items = Vec::with_capacity(self.items.len());
        for item in std::mem::take(&mut self.items) {
            match item {
                Item::Bookmark(mut b) => {
                    if keep(&mut b, &mut kept) {
                        items.push(Item::Bookmark(b));
                    } else {
                        dropped += 1;
                    }
                }
                Item::Folder(mut f) => {
                    if folders >= MAX_FOLDERS {
                        dropped += f.items.len();
                        repairs.push("a folder over the limit removed".into());
                        continue;
                    }
                    folders += 1;
                    f.title = clean_title(&f.title);
                    if f.title.is_empty() {
                        f.title = "Folder".into();
                    }
                    for mut b in std::mem::take(&mut f.items) {
                        if keep(&mut b, &mut kept) {
                            f.items.push(b);
                        } else {
                            dropped += 1;
                        }
                    }
                    items.push(Item::Folder(f));
                }
            }
        }
        let mut max_id = 0u64;
        for_each_id(&mut items, |id| max_id = max_id.max(*id));
        let mut seen = HashSet::new();
        let mut next = max_id + 1;
        let mut renumbered = 0usize;
        for_each_id(&mut items, |id| {
            if *id == 0 || !seen.insert(*id) {
                *id = next;
                seen.insert(next);
                next += 1;
                renumbered += 1;
            }
        });
        self.items = items;
        self.next_id = self.next_id.max(next);
        if renumbered > 0 {
            repairs.push(format!("{renumbered} missing or duplicate id(s) renumbered"));
        }
        if dropped > 0 {
            repairs.push(format!("{dropped} unusable bookmark(s) removed"));
        }
        repairs
    }
}

fn edit_bookmark(b: &mut Bookmark, title: &str, url: Option<String>) {
    if let Some(u) = url {
        if u != b.url {
            b.icon = None; // the icon belonged to the old address
        }
        b.url = u;
    }
    b.title = bookmark_title(title, &b.url);
}

// ------------------------------------------------------------------ the bookmarks file format

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Decode the character references a bookmarks file uses. Unknown ones stay as written.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let semi = after.char_indices().take(12).find(|&(_, c)| c == ';').map(|(i, _)| i);
        let decoded = semi.and_then(|semi| {
            let name = &after[..semi];
            let c = match name {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some(' '),
                _ => {
                    let n = if let Some(hex) = name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        name.strip_prefix('#').and_then(|d| d.parse::<u32>().ok())
                    };
                    n.and_then(char::from_u32)
                }
            };
            c.map(|c| (c, semi))
        });
        match decoded {
            Some((c, semi)) => {
                out.push(c);
                rest = &after[semi + 1..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The value of one attribute in a tag's attribute text (case-insensitive name).
fn attribute(attrs: &str, wanted: &str) -> Option<String> {
    let b = attrs.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        let start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'=' && b[i] != b'>' {
            i += 1;
        }
        let name = &attrs[start..i];
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = None;
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                let vs = i + 1;
                let ve = attrs[vs..].bytes().position(|c| c == q).map_or(b.len(), |p| vs + p);
                value = Some(&attrs[vs..ve]);
                i = (ve + 1).min(b.len());
            } else {
                let vs = i;
                while i < b.len() && !b[i].is_ascii_whitespace() {
                    i += 1;
                }
                value = Some(&attrs[vs..i]);
            }
        }
        if name.eq_ignore_ascii_case(wanted) {
            return value.map(unescape);
        }
        if name.is_empty() && value.is_none() {
            i += 1; // a stray character: move on
        }
    }
    None
}

/// Text up to the closing tag `close` (lower case, e.g. "</a"), with any tags inside removed.
/// Returns the text and the position after the closing tag.
fn text_until(html: &str, lower: &str, from: usize, close: &str) -> (String, usize) {
    let (end, after) = match lower[from..].find(close) {
        Some(p) => {
            let end = from + p;
            let after = lower[end..].find('>').map_or(html.len(), |q| end + q + 1);
            (end, after)
        }
        None => (html.len(), html.len()),
    };
    let mut text = String::new();
    let mut in_tag = false;
    for c in html[from..end].chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            c if !in_tag => text.push(c),
            _ => {}
        }
    }
    (unescape(&text), after)
}

/// Read the links of a bookmarks file (Chrome, Edge, Firefox, UNTRACE and others). Tolerant:
/// unknown tags are skipped and broken markup ends the file rather than failing it.
pub fn parse_html(html: &str) -> Vec<ImportedLink> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    // One entry per open list: the folder it belongs to (None for lists outside any folder).
    let mut lists: Vec<Option<String>> = Vec::new();
    let mut pending: Option<String> = None;
    let mut i = 0;
    while let Some(off) = html[i..].find('<') {
        let start = i + off;
        if lower[start..].starts_with("<!--") {
            match lower[start..].find("-->") {
                Some(p) => {
                    i = start + p + 3;
                    continue;
                }
                None => break,
            }
        }
        // The tag ends at the first '>' outside quotes.
        let bytes = html.as_bytes();
        let mut j = start + 1;
        let mut quote = 0u8;
        while j < bytes.len() {
            let c = bytes[j];
            if quote != 0 {
                if c == quote {
                    quote = 0;
                }
            } else if c == b'"' || c == b'\'' {
                quote = c;
            } else if c == b'>' {
                break;
            }
            j += 1;
        }
        if j >= bytes.len() {
            break;
        }
        let inner = &html[start + 1..j];
        i = j + 1;
        let closing = inner.starts_with('/');
        let body = inner.trim_start_matches('/');
        let name_len = body.bytes().take_while(u8::is_ascii_alphanumeric).count();
        let name = body[..name_len].to_ascii_lowercase();
        let attrs = &body[name_len..];
        match (closing, name.as_str()) {
            (false, "dl") => lists.push(pending.take()),
            (true, "dl") => {
                lists.pop();
                pending = None;
            }
            (false, "h3") => {
                let (text, after) = text_until(html, &lower, i, "</h3");
                pending = Some(clean_title(&text));
                i = after;
            }
            (false, "a") => {
                pending = None;
                let href = attribute(attrs, "href").unwrap_or_default();
                let (text, after) = text_until(html, &lower, i, "</a");
                i = after;
                if out.len() >= MAX_IMPORT_LINKS {
                    break;
                }
                out.push(ImportedLink {
                    folders: lists
                        .iter()
                        .flatten()
                        .filter(|f| !f.is_empty())
                        .take(MAX_IMPORT_DEPTH)
                        .cloned()
                        .collect(),
                    title: text,
                    url: href,
                });
            }
            _ => {}
        }
    }
    out
}

// ------------------------------------------------------------------------------- the store

/// The bookmarks on disk. Changes are made to a copy and kept only if the file was written.
pub struct BookmarkStore {
    path: PathBuf,
    data: BookmarkFile,
}

fn seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl BookmarkStore {
    /// Read `bookmarks.json` in `dir`. A missing file is an empty list (written at the first
    /// change); an unreadable one is set aside, never deleted, and the list starts empty.
    pub fn open(dir: &Path) -> io::Result<(Self, LoadOutcome)> {
        fs::create_dir_all(dir)?;
        let mut store = Self {
            path: dir.join("bookmarks.json"),
            data: BookmarkFile::default(),
        };
        let meta = match fs::metadata(&store.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((store, LoadOutcome::Created)),
            Err(e) => return Err(e),
            Ok(m) => m,
        };
        if meta.len() > MAX_FILE_BYTES {
            let o = store.set_aside("the bookmarks file is unexpectedly large");
            return Ok((store, o));
        }
        let Ok(text) = fs::read_to_string(&store.path) else {
            let o = store.set_aside("the bookmarks file is not valid text");
            return Ok((store, o));
        };
        let mut parsed: BookmarkFile = match serde_json::from_str(&text) {
            Ok(p) => p,
            Err(e) => {
                let o = store.set_aside(&format!("the bookmarks file could not be read ({e})"));
                return Ok((store, o));
            }
        };
        let repairs = parsed.validate();
        store.data = parsed;
        if repairs.is_empty() {
            return Ok((store, LoadOutcome::Loaded));
        }
        // Keep the file as it was before writing the repaired one.
        let _ = fs::copy(
            &store.path,
            store
                .path
                .with_file_name(format!("bookmarks.before-repair-{}.json", seconds())),
        );
        write_atomic(&store.path, &store.data)?;
        Ok((store, LoadOutcome::Repaired { repairs }))
    }

    fn set_aside(&mut self, reason: &str) -> LoadOutcome {
        let backup = self
            .path
            .with_file_name(format!("bookmarks.invalid-{}.json", seconds()));
        let backup = fs::rename(&self.path, &backup)
            .ok()
            .map(|_| backup.display().to_string());
        self.data = BookmarkFile::default();
        LoadOutcome::Reset {
            reason: reason.to_string(),
            backup,
        }
    }

    pub fn data(&self) -> &BookmarkFile {
        &self.data
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Change the bookmarks and write them. Nothing changes if `f` fails or the write does.
    pub fn change<T>(&mut self, f: impl FnOnce(&mut BookmarkFile, u64) -> Result<T, String>) -> Result<T, String> {
        let mut next = self.data.clone();
        let out = f(&mut next, seconds())?;
        write_atomic(&self.path, &next).map_err(|e| format!("The bookmarks could not be saved ({e})."))?;
        self.data = next;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("untrace-bookmarks-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    const PNG: &str = "data:image/png;base64,iVBORw0KGgo=";

    #[test]
    fn only_web_addresses_are_kept() {
        assert_eq!(normalize_url(" https://example.com ").unwrap(), "https://example.com/");
        assert_eq!(
            normalize_url("http://a.example/x?y#z").unwrap(),
            "http://a.example/x?y#z"
        );
        for bad in [
            "",
            "javascript:alert(1)",
            "JAVASCRIPT:alert(1)",
            "file:///C:/Windows",
            "data:text/html,hi",
            "about:blank",
            "edge://settings",
            "example.com",
            "https://",
        ] {
            assert!(normalize_url(bad).is_err(), "{bad} accepted");
        }
        assert!(normalize_url(&format!("https://e.example/{}", "a".repeat(MAX_URL))).is_err());
    }

    #[test]
    fn titles_are_one_line_and_bounded() {
        assert_eq!(clean_title("  a\n\tb\u{7}  c "), "a b c");
        assert_eq!(clean_title(&"x".repeat(1000)).chars().count(), MAX_TITLE);
        // Cleaning is stable, also when the cut falls just after a space.
        let t = format!("{} tail", "y".repeat(MAX_TITLE - 1));
        assert_eq!(clean_title(&t), "y".repeat(MAX_TITLE - 1));
        assert_eq!(clean_title(&clean_title(&t)), clean_title(&t));
        assert_eq!(bookmark_title("  ", "https://www.example.com/p"), "www.example.com");
    }

    #[test]
    fn only_small_png_icons_are_kept() {
        assert_eq!(clean_icon(Some(PNG)).as_deref(), Some(PNG));
        assert_eq!(clean_icon(Some("data:image/svg+xml;base64,PHN2Zz4=")), None);
        assert_eq!(clean_icon(Some("data:image/png;base64,<script>")), None);
        assert_eq!(clean_icon(Some("https://example.com/favicon.ico")), None);
        let big = format!("{ICON_PREFIX}{}", "A".repeat(MAX_ICON));
        assert_eq!(clean_icon(Some(&big)), None);
        assert_eq!(clean_icon(None), None);
    }

    #[test]
    fn add_edit_move_and_remove() {
        let mut f = BookmarkFile::default();
        let a = f.add("A", "https://a.example", Some(PNG), None, 1).unwrap();
        let docs = f.add_folder("Docs", 1).unwrap();
        let b = f.add("", "https://b.example/x", None, Some(docs), 2).unwrap();
        assert_eq!(f.bookmark_count(), 2);
        assert_eq!(f.find_url("https://b.example/x"), Some(b));
        assert_eq!(f.find_url("https://a.example/"), Some(a));
        assert_eq!(f.find_url("https://c.example"), None);
        assert!(f.add("x", "javascript:alert(1)", None, None, 3).is_err());
        assert!(f.add("x", "https://c.example", None, Some(999), 3).is_err());
        assert!(f.add_folder(" \n ", 3).is_err());

        // A new address drops the old address's icon.
        f.edit(a, "Renamed", Some("https://a2.example")).unwrap();
        match &f.items[0] {
            Item::Bookmark(bm) => {
                assert_eq!(
                    (bm.title.as_str(), bm.url.as_str(), bm.icon.as_deref()),
                    ("Renamed", "https://a2.example/", None)
                )
            }
            other => panic!("{other:?}"),
        }
        assert!(f.edit(a, "x", Some("file:///c:/")).is_err());
        f.edit(docs, "Documents", None).unwrap();
        assert!(f.edit(docs, "", None).is_err());

        // Into a folder, out again, reordered; folders stay one level.
        f.move_to(a, Some(docs), 0).unwrap();
        assert_eq!(f.items.len(), 1);
        f.move_to(b, None, 0).unwrap();
        assert!(matches!(&f.items[0], Item::Bookmark(x) if x.id == b));
        let other = f.add_folder("Other", 4).unwrap();
        assert!(f.move_to(other, Some(docs), 0).is_err());
        f.move_to(other, None, 0).unwrap();
        assert!(matches!(&f.items[0], Item::Folder(x) if x.id == other));

        f.remove(docs).unwrap();
        assert_eq!(f.bookmark_count(), 1);
        assert!(f.remove(docs).is_err());
        let ids: Vec<u64> = f
            .items
            .iter()
            .map(|i| match i {
                Item::Bookmark(b) => b.id,
                Item::Folder(f) => f.id,
            })
            .collect();
        assert_eq!(ids, vec![other, b]);
    }

    #[test]
    fn the_limits_hold() {
        let mut f = BookmarkFile::default();
        for n in 0..MAX_BOOKMARKS {
            f.add("", &format!("https://e{n}.example"), None, None, 0).unwrap();
        }
        assert!(f.add("", "https://one-more.example", None, None, 0).is_err());
        let r = f.import(
            vec![ImportedLink {
                folders: vec![],
                title: "t".into(),
                url: "https://over.example".into(),
            }],
            0,
        );
        assert_eq!(r.over_limit, 1);
    }

    const CHROME: &str = r#"<!DOCTYPE NETSCAPE-Bookmark-file-1>
<!-- This is an automatically generated file. -->
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE>
<H1>Bookmarks</H1>
<DL><p>
    <DT><H3 ADD_DATE="1" LAST_MODIFIED="2" PERSONAL_TOOLBAR_FOLDER="true">Bookmarks bar</H3>
    <DL><p>
        <DT><A HREF="https://news.example/" ADD_DATE="3" ICON="data:image/png;base64,AAAA">News &amp; more</A>
        <DT><H3 ADD_DATE="4">Work</H3>
        <DL><p>
            <DT><A HREF="https://docs.example/a?b=1&amp;c=2">Docs &#8211; &lt;team&gt;</A>
            <DT><A HREF="javascript:alert(document.cookie)">Bookmarklet</A>
        </DL><p>
    </DL><p>
    <DT><A HREF='http://plain.example'>Plain</A>
    <DT><A HREF="file:///C:/secret.txt">Local file</A>
</DL><p>
"#;

    #[test]
    fn a_chrome_file_imports_with_flattened_folders() {
        let links = parse_html(CHROME);
        assert_eq!(links.len(), 5);
        assert_eq!(links[0].folders, vec!["Bookmarks bar"]);
        assert_eq!(links[0].title, "News & more");
        assert_eq!(links[1].folders, vec!["Bookmarks bar", "Work"]);
        assert_eq!(links[1].url, "https://docs.example/a?b=1&c=2");
        assert_eq!(links[1].title, "Docs \u{2013} <team>");
        assert!(links[3].folders.is_empty());

        let mut f = BookmarkFile::default();
        let r = f.import(links.clone(), 10);
        assert_eq!(
            r,
            ImportReport {
                added: 3,
                folders_added: 2,
                duplicates: 0,
                unsupported: 2,
                over_limit: 0
            }
        );
        let names: Vec<&str> = f
            .items
            .iter()
            .filter_map(|i| match i {
                Item::Folder(x) => Some(x.title.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(names, vec!["Bookmarks bar", "Bookmarks bar / Work"]);
        // Icons from a file are not kept.
        assert!(f.items.iter().all(|i| match i {
            Item::Bookmark(b) => b.icon.is_none(),
            Item::Folder(x) => x.items.iter().all(|b| b.icon.is_none()),
        }));

        // The same file again adds nothing.
        let again = f.import(links, 11);
        assert_eq!((again.added, again.duplicates, again.folders_added), (0, 3, 0));
    }

    #[test]
    fn export_then_import_gives_the_same_bookmarks() {
        let mut f = BookmarkFile::default();
        f.add(
            "Quotes \" & <tags> 'here'",
            "https://q.example/?a=1&b=2",
            Some(PNG),
            None,
            5,
        )
        .unwrap();
        let folder = f.add_folder("Folder & co", 6).unwrap();
        f.add("Inside", "https://in.example/", None, Some(folder), 7).unwrap();
        let html = f.export_html();
        assert!(html.starts_with("<!DOCTYPE NETSCAPE-Bookmark-file-1>"));
        assert!(html.contains("&amp;b=2") && !html.contains("<tags>"));

        let mut g = BookmarkFile::default();
        let r = g.import(parse_html(&html), 0);
        assert_eq!((r.added, r.folders_added, r.unsupported), (2, 1, 0));
        let flat = |x: &BookmarkFile| -> Vec<(String, String)> {
            x.items
                .iter()
                .flat_map(|i| match i {
                    Item::Bookmark(b) => vec![(b.title.clone(), b.url.clone())],
                    Item::Folder(fo) => fo
                        .items
                        .iter()
                        .map(|b| (format!("{}/{}", fo.title, b.title), b.url.clone()))
                        .collect(),
                })
                .collect()
        };
        assert_eq!(flat(&f), flat(&g));
    }

    #[test]
    fn broken_files_never_panic() {
        for input in [
            "",
            "<",
            "<a href=\"https://x.example",
            "<!-- never closed",
            "<DL><DL><DL></DL></DL></DL></DL></DL>",
            "<H3>no end",
            "<A HREF=https://u.example>unquoted</A><A HREF='x'",
            "&#xFFFFFFFF; &#0; &#55296; &amp &;",
            "<a href=\"&#x110000;\">x</a>",
            "\u{1F600}<a href=\"https://e.example\">\u{1F600}</a>\u{1F600}",
        ] {
            let _ = BookmarkFile::default().import(parse_html(input), 0);
        }
        let deep = "<DT><H3>f</H3><DL>".repeat(50) + "<A HREF=\"https://deep.example\">d</A>";
        let links = parse_html(&deep);
        assert_eq!(links[0].folders.len(), MAX_IMPORT_DEPTH);
    }

    #[test]
    fn the_store_keeps_what_it_cannot_read() {
        let dir = temp_dir("store");
        let (mut s, o) = BookmarkStore::open(&dir).unwrap();
        assert_eq!(o, LoadOutcome::Created);
        assert!(!s.path().exists(), "no file before the first bookmark");
        let id = s
            .change(|f, now| f.add("A", "https://a.example", None, None, now))
            .unwrap();
        // A failed change leaves the bookmarks as they were.
        assert!(s.change(|f, now| f.add("B", "javascript:x", None, None, now)).is_err());
        let (s2, o2) = BookmarkStore::open(&dir).unwrap();
        assert_eq!(o2, LoadOutcome::Loaded);
        assert_eq!(s2.data().find_url("https://a.example"), Some(id));
        assert_eq!(s2.data().bookmark_count(), 1);

        // Damaged: set aside under another name, never deleted.
        fs::write(s.path(), b"{ not json").unwrap();
        let (s3, o3) = BookmarkStore::open(&dir).unwrap();
        assert!(matches!(o3, LoadOutcome::Reset { backup: Some(_), .. }));
        assert_eq!(s3.data().bookmark_count(), 0);
        let set_aside = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().starts_with("bookmarks.invalid-"));
        assert!(set_aside);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tampered_file_is_repaired_and_the_original_kept() {
        let dir = temp_dir("repair");
        let path = dir.join("bookmarks.json");
        fs::write(
            &path,
            r#"{"schema":1,"next_id":1,"items":[
                {"kind":"bookmark","id":5,"title":"ok","url":"https://ok.example"},
                {"kind":"bookmark","id":5,"title":"dup id","url":"https://dup.example"},
                {"kind":"bookmark","id":6,"title":"script","url":"javascript:alert(1)"},
                {"kind":"folder","id":7,"title":"F","items":[
                    {"kind":"bookmark","id":0,"title":"zero","url":"https://z.example","icon":"data:text/html,x"}]}
            ]}"#,
        )
        .unwrap();
        let (s, o) = BookmarkStore::open(&dir).unwrap();
        let LoadOutcome::Repaired { repairs } = o else {
            panic!("{o:?}")
        };
        assert_eq!(repairs.len(), 2, "{repairs:?}");
        let f = s.data();
        assert_eq!(f.bookmark_count(), 3);
        let mut ids = Vec::new();
        let mut items = f.items.clone();
        for_each_id(&mut items, |id| ids.push(*id));
        let unique: HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len());
        assert!(ids.iter().all(|&id| id > 0 && id < f.next_id));
        let kept = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().starts_with("bookmarks.before-repair-"));
        assert!(kept);
        let _ = fs::remove_dir_all(&dir);
    }
}
