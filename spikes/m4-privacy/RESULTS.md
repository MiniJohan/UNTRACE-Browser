# M4 — Engine behaviour probe (2026-11-22)

`crates/untrace-webview/examples/m4_probe.rs` drives the real content host against a local HTTP fixture on `127.0.0.1`. No external network is used. The fixture logs every request line it receives, so what reached the "server" is observed directly. WebView2 Runtime 157.0.4341.60.

Run it with:

```
cargo run -p untrace-webview --example m4_probe -- <data-dir> <out.json>
```

Set `M4_CLEAR_SETTINGS=1` to add the engine's "site settings" kind to the final clearing. Outputs: `probe-clear-all.json` and `probe-clear-all-with-site-settings.json`.

## Tracking parameters (D-027)

The design answers a page or frame GET request carrying listed parameters with a `307` to the cleaned address, from `WebResourceRequested`.

| Case | Server received | Page's own address | Counted |
|---|---|---|---|
| `/landing?utm_source=a&keep=1&fbclid=x` | `GET /landing?keep=1` only | `…/landing?keep=1` | 2 (`utm_source`, `fbclid`) |
| `/r` → server `302` to `/landing?utm_source=redir&keep=1` | `GET /r`, then `GET /landing?keep=1` | `…/landing?keep=1` | 1 |
| frame `src=/landing?utm_medium=frame&k=2` | `GET /landing?k=2` | frame: `…/landing?k=2` | 1 |
| form `POST /landing?utm_source=post&p=1` | `POST /landing?utm_source=post&p=1`, body `a=b` | unchanged | — (left alone, by design) |

The request event fires for each hop of a server redirect, so parameters added by a redirect are removed too.

Pages served from a folder mapped to a host name (`SetVirtualHostNameToFolderMapping`, which only the self-check uses) do not raise the request event for their own document, so their parameters stay. Self-check 34 therefore uses an unresolvable canary host, where the cleaned address must appear in UNTRACE's error panel.

## Temporary tabs (D-036, D-028)

- **Isolation.** The temporary tab sees its own cookie and local-storage value. A normal tab sees neither, and the standard profile's cookie list does not include it.
- **Tracking prevention.** Read back as `balanced` from both profiles.
- **Worker requests.** A temporary tab's shared-worker request to the tracker canary is blocked and counted once. Each profile has its own owner tab.
- **Folders on disk.**
  - While the temporary tab is open: `WV2Profile_standard` and `WV2Profile_temp-<32 hex>`.
  - After it closes, the temporary folder remains, nearly empty. `remove_leftover_temp_profiles` removes it once the engine has stopped; UNTRACE calls it at start.
- **Residue.** After the tab closes, no file in the data folder contains the temporary marker, which was written to a cookie, local storage and IndexedDB.
- **Positive control.** The normal profile's marker is found on disk (Local Storage and IndexedDB files), so the scan does detect data that is there. Cookie values are encrypted at rest (S5), so cookies cannot serve as a disk control.

## Cookies and site data

- **Listing.** The site is listed with 1 cookie. Grouping is by registrable domain, and the cookie domains are kept for display.
- **Delete one site.** The engine then reports 0 cookies left. After reloading, the page sees neither its cookie nor its local storage: `Storage.clearDataForOrigin` worked through the host-side DevTools channel with developer tools off.
- **Clearing the cache.** `ClearBrowsingData(DISK_CACHE)` completes.

## What the engine keeps after clearing everything (D-039)

Steps:

1. Leave the site (`about:blank`).
2. Run `ClearBrowsingData` with all site data and service workers, the disk cache, and browsing and download history.
3. Wait 15 s; Chromium commits its preferences file about every 10 s.
4. Close the engine.
5. Search every file for the site.

| After clearing with | Files still naming the visited origin |
|---|---|
| site data + cache + history | `WV2Profile_standard\Preferences`: `profile.content_settings.exceptions.site_engagement["http://127.0.0.1:<port>,*"]` (score, last engagement time) |
| … + site settings (`SETTINGS`) | the same entry |
| … + "all profile data" (`ALL_PROFILE`) | the same entry |

- **Media engagement.** Entries are removed by the clearing. In an earlier run the open page re-created one when the engine closed, so a site must be left before clearing.
- **DIPS.** Bounce-tracking records appeared in `DIPS-wal` while the engine ran, but not after it closed.
- **Site engagement.** None of the engine's delete functions remove it. It is a list of origins the user visited, with scores. Chromium lets the scores decay over weeks, but there is no supported way to clear them. D-039 is open: either document it only, or have UNTRACE remove those entries from `Preferences` at start-up while the engine is not running.

## Start-up clean-up of engine files (D-039, accepted)

The product owner chose removal. A hands-on restart then showed a second record. `Local State` keeps every temporary profile by name and records the last one as `last_used`. The engine reopens that profile at the next start, which recreated the temporary folder UNTRACE had just removed.

The clean-up (`untrace-webview/src/engine_files.rs`):
1. Removes the temporary-profile entries from `Local State`.
2. Empties the engagement lists in each normal profile's `Preferences`.
3. Removes the leftover folders.

The probe (`probe-engine-file-cleanup.json`) runs it on the folder left by the steps above. It removed 1 engagement record, 3 temporary-profile entries and 1 folder, and read every file back clean. After it:
- no file names the visited site;
- the engine restarts on the edited files and loads a page;
- the temporary folder does not come back;
- `last_used` is gone.
