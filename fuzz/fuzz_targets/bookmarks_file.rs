//! D-055: bookmarks files. An imported HTML file is untrusted (byte 0 even), and so is
//! UNTRACE's own bookmarks.json after tampering (byte 0 odd). Neither may crash UNTRACE or put
//! anything but a web address, a bounded one-line title and a small PNG icon into the store;
//! exporting and importing again keeps every bookmark.
#![no_main]
use std::collections::HashSet;

use libfuzzer_sys::fuzz_target;
use untrace_core::bookmarks::{
    self, BookmarkFile, Item, MAX_BOOKMARKS, MAX_FOLDERS, MAX_TITLE, clean_icon, normalize_url, parse_html,
};

fn check(f: &BookmarkFile) {
    assert!(f.bookmark_count() <= MAX_BOOKMARKS);
    assert!(f.folder_count() <= MAX_FOLDERS);
    let mut ids = HashSet::new();
    let title_ok = |t: &str| {
        assert!(!t.is_empty() && t.chars().count() <= MAX_TITLE, "title {t:?}");
        assert!(!t.chars().any(char::is_control), "control character in {t:?}");
    };
    let bookmark = |b: &bookmarks::Bookmark, ids: &mut HashSet<u64>| {
        assert_eq!(normalize_url(&b.url).as_deref(), Ok(b.url.as_str()), "address {:?}", b.url);
        title_ok(&b.title);
        if let Some(i) = &b.icon {
            assert_eq!(clean_icon(Some(i)).as_deref(), Some(i.as_str()));
        }
        assert!(b.id > 0 && b.id < f.next_id && ids.insert(b.id), "id {}", b.id);
    };
    for item in &f.items {
        match item {
            Item::Bookmark(b) => bookmark(b, &mut ids),
            Item::Folder(folder) => {
                assert!(folder.id > 0 && folder.id < f.next_id && ids.insert(folder.id));
                assert!(!folder.title.is_empty() && folder.title.chars().count() <= MAX_TITLE);
                for b in &folder.items {
                    bookmark(b, &mut ids);
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, body)) = data.split_first() else { return };
    let mut f = if mode % 2 == 0 {
        let mut f = BookmarkFile::default();
        let _ = f.import(parse_html(&String::from_utf8_lossy(body)), 0);
        f
    } else {
        let Ok(mut f) = serde_json::from_slice::<BookmarkFile>(body) else { return };
        let _ = f.validate();
        f
    };
    check(&f);
    // A validated file is stable: validating again changes nothing.
    let before = f.clone();
    assert!(f.validate().is_empty(), "second validation repaired something");
    assert_eq!(before, f);
    // Export, then import into an empty list: every bookmark comes back (or is a duplicate of
    // one in the same folder).
    let mut g = BookmarkFile::default();
    let r = g.import(parse_html(&f.export_html()), 0);
    assert_eq!(r.unsupported, 0, "an exported address did not import");
    assert_eq!(r.added + r.duplicates + r.over_limit, f.bookmark_count());
    check(&g);
});
