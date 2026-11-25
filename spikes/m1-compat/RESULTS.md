# M1 compatibility check — 53 real sites

Date: 2026-11-21 · UNTRACE 0.1.0 (M1 content host), WebView2 Runtime 157.0.4341.60, Windows 11. Run approved by the product owner.

**Method.**
- [`crates/untrace-webview/examples/compat.rs`](../../crates/untrace-webview/examples/compat.rs) drives the real content host: dedicated environment, M1 hardening, M1 interim defaults (permissions denied, pop-ups without a click blocked, external apps never launched, certificate errors refused).
- It walks [`sites.txt`](sites.txt) in one tab, with a fresh profile and no sign-ins.
- Per site it records the load result, HTTP status, final URL, title, rendered text length, and what UNTRACE blocked.
- Raw data: [`results.json`](results.json), [`run.log`](run.log).

**Coverage.** News and reference (12), Swedish public services (4), video and media (6), social (5), search and maps (5), shopping and travel (6), vendors (5), web apps and sign-in pages (7), payments and banking front pages (3).

## Result

| Outcome | Sites |
|---|---|
| Loaded with content, HTTP 200 | **50 / 53** on the first pass |
| First-visit bot check, fine on revisit | 3: nytimes.com (403 + challenge frame), reuters.com (challenge, no text), amazon.com ("Continue shopping" page). Re-tested: all three HTTP 200 with full content (nytimes twice). |
| Failed because of something UNTRACE blocked | **0**. No permission request, pop-up, external-app launch or certificate error was recorded on any page. |
| Renderer crashes | 0 |

Expected redirects:
- `google.com/maps` → `consent.google.com` (EU consent with a fresh profile)
- `docs.google.com` → `accounts.google.com`
- `mail.proton.me` → `account.proton.me`
- `outlook.live.com` → `microsoft.com`
- `office.com` → `m365.cloud.microsoft`
- `notion.so` → `notion.com`
- `airbnb.com` → `airbnb.se`
- `spotify.com` → `open.spotify.com`

Load times (navigation start → complete, first pass) were mostly 0.3–1.5 s; the slowest was microsoft.com at 3.4 s. They are informational only: there is no filtering in M1, so there is nothing yet to compare overhead against. The filtering-overhead measurement belongs to M3.

## Limits of this check

- Front pages only, no sign-ins, no media playback, no interaction. DRM playback (Netflix, Spotify) and video calls are not covered. Camera and microphone requests will go through the M2 permission prompts.
- A fresh profile triggers first-visit bot checks. Whether WebView2's identifiability (M0/S1) makes those more frequent than in Edge or Chrome was not measured.
- One run from one network; sites change daily. Re-run with `cargo run --release -p untrace-webview --example compat -- spikes/m1-compat/sites.txt out.json <data-dir>` at every milestone.
