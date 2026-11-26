# UNTRACE — Testing Strategy

Principle: **a protection that is not tested does not exist.** Every protection in the registry has (1) unit tests for its logic, (2) an integration test against a real WebView2 instance, and (3) a runtime self-test that the user can run from Diagnostics.

---

## 1. Test layers

| Layer | Tooling | Runs | Covers |
|---|---|---|---|
| Unit | `cargo test`, Vitest (UI logic only) | Every commit | Settings schema, protection registry state machine, URL/scheme policy, HTTPS upgrade logic, param cleanup, exception matching, list validation, proxy parser, IPC input validation |
| Property / fuzz | `proptest`, `cargo fuzz` (nightly job) | Nightly | Address-field parsing, settings loader, proxy request parser, list-update validator, URL display (IDN/punycode) |
| Integration | Rust test harness driving a real window + WebView2 on Windows; local fixture server | Every PR (Windows runner) | Each protection end-to-end against fixture sites |
| Protection self-tests | Built into the app (Diagnostics) | On demand + after each settings change | Verified state on the user's machine |
| Performance | Benchmarks + page-load corpus | Per milestone, release | Matching cost, page-load overhead, memory, startup |
| Privacy leak | Scripted checks (DNS cache, connection log, disk residue) | Per milestone, release | DNS leaks, outbound requests, data left behind |
| Manual | Checklist per milestone | Milestone exit | UI, accessibility, real-world sites |

## 2. Fixture environment

- Local HTTPS fixture server (Rust test binary) serving `*.test` hosts, mapped to loopback in test builds only (Chromium `--host-resolver-rules`, or the UNTRACE proxy's resolver in test mode) — no external network needed for integration tests.
- Fixture certificates come from a **test-only** CA. No machine or user trust store is modified. A test-only build feature (`fixture-ca`) accepts exactly that CA through `ServerCertificateErrorDetected` (authority errors only, fingerprint-pinned); bad-certificate fixtures use separate certificates that remain rejected. The feature is compiled out of release builds and a CI check asserts it.
- Fixture sites: first-party page with third-party iframe (cross-origin), tracker scripts/pixels on reserved test domains, service worker + shared worker + dedicated worker issuing requests, WebSocket client, pop-up/opener flow, download links (exe, zip, pdf), permission requests, HTTP-only site, invalid/expired/self-signed/wrong-host certificates, strict-CSP page, link-decorated URLs, third-party cookie setter.

## 3. Protection verification matrix

| Protection | Integration test (expected) | Runtime self-test |
|---|---|---|
| Ad / tracker blocking | Requests to test-rule hosts from main frame, cross-origin iframe and workers are blocked; counters increment; allowed requests untouched | **M3:** self-check 26–28, 31 (canary hosts; page, shared worker, Settings switch) |
| Site exceptions | Same page with exception → requests allowed; removal restores blocking | **M3:** self-check 32 |
| Malicious domains | Navigation → interstitial naming the list; sub-resource blocked; network-layer backstop blocks WebSocket (if enabled) | **M3:** self-check 27, 29, 30 (WebSocket backstop: M5) |
| Cosmetic filtering | Hidden elements absent from layout on normal and CSP-strict pages and in cross-origin frames | Test page element hidden |
| Edge tracking prevention | Read-back equals setting; known-tracker fixture storage blocked at Strict | **M4:** self-check 33 (read-back of both profiles; Strict and back, verified). Known-tracker storage behaviour: S6 |
| Third-party cookies | Per D-010/D-037: no "block all"; known trackers restricted by tracking prevention | Read-back (as above) |
| Param cleanup | `?utm_source=…&gclid=…&id=7` → `?id=7`; POST navigations untouched | **M4:** self-check 34; local fixture (`examples/m4_probe.rs`): server never receives them, incl. after a server redirect and in frames; POST untouched |
| HTTPS-only | `http://` upgraded; failure page shown; "continue over HTTP" scoped to site + session | Navigation test |
| Certificates | Each bad-cert fixture → UNTRACE error page; no way to proceed | — |
| Permissions | Default deny/ask honoured; read-back lists decisions; reset works | Read-back |
| Downloads | Location prompt; executable warning; Mark-of-the-Web (`Zone.Identifier`) present | — |
| Temporary sessions | Cookies/storage invisible to standard profile; nothing remains on disk after close (S5 method) | **M4:** self-check 35 (with a positive control from a normal tab) |
| Cookie and site-data manager | Site listed with its cookies; deleting it leaves none (read back) and its storage is gone | **M4:** self-check 36, 37 |
| Element hiding | Canary and real rules hidden in a strict-CSP page and a cross-origin frame; the switch and per-site exceptions turn it off | **M6:** self-check 45, 46; unit tests in `untrace-filter` (`cosmetic`); spike `spikes/m6-cosmetic/RESULTS.md` |
| Clear on exit | Selected kinds empty after restart | **M4:** clean-exit step requires the cache clearing to finish (`exit-clear.json` = done); start-up fallback: unit tests in `privacy.rs` |
| Encrypted DNS | Bypass: an engine started without the proxy arguments never delivers the start-up check's request, so Settings shows *not verified* (M5 probe; unit tests in `network.rs`). Proxy counters > 0; Chromium net-log (test builds, `--log-net-log`) shows no `HOST_RESOLVER_MANAGER_JOB` / `DNS_TRANSACTION` for page hosts; proxy stopped → loads fail and fixture sees nothing | **M5:** start-up route check (a request from the engine must reach the proxy with credentials) read back in Settings and Diagnostics; self-check 38–40, 43, 44; M5 probe (net-log, fail closed, first navigation of a fresh profile); `untrace-net` example `doh` (each provider answers over DoH; a wrong path fails with 9002) |
| Local-network protection | Requests from a public page to loopback/local addresses blocked and counted; allowed per site; public names resolving locally refused at the network layer | **M5:** self-check 41, 42; unit tests in `untrace-net` (`addr`, rebinding decisions) |
| External schemes | Prompt shown; denied schemes never launch | — |
| Content isolation | In content views: `__TAURI_INTERNALS__`, `chrome.webview.postMessage`, host objects all undefined | Isolation probe page |

## 4. Performance budgets (initial, revisited after M0)

| Metric | Budget |
|---|---|
| Request match (adblock-rust) | ≤ 0.2 ms p99 — **M3: p99 6.8 µs** (bundled lists, release build, 50k requests) |
| Page-load overhead vs. bare WebView2 (50-site corpus, filtering on) | ≤ 10 % p95 — **M3: met.** Paired run (alternating off/on, fresh profiles; 143 pairs incl. 6 repeats of the 7 slowest sites): p95 −0.1 % host-timed, −0.5 % by the page's load event; median +3.3 % / −4.4 %. Corpus alone: p95 +4.6 % / −4.0 %. No site was consistently slower (`spikes/m3-filtering/RESULTS.md`) |
| Page-load overhead of the network layer (corpus, filtering on in both) | ≤ 10 % p95 — **M5: met.** 101 pairs, Automatic mode: p95 −18.5 % host-timed, −17.7 % load event (no measurable overhead; Windows' shared DNS cache helps the network layer) |
| Page-load overhead of element hiding (corpus, filtering on in both) | ≤ 10 % p95 — **M6: accepted on the typical cost (product owner, 2026-11-23); p95 not settled, may be re-measured later.** Split design: the median of per-pair ratios is 1.039 host-timed and 1.072 load event (≈ 4 % typical). The p95 ranged from −0.3 % to +27.1 % across runs on a noisy network. The first single-script design measured load-event p95 +12.0 % (`spikes/m6-cosmetic/RESULTS.md`) |
| Cold start to first paint of UI | ≤ 1.0 s on reference machine |
| Engine rebuild after list update | Off UI thread; ≤ 3 s — **M3: 70 ms build on the update worker; UI thread loads the verified cache in 2.1 ms** |
| Idle memory, one blank tab | Recorded in M0; regression > 15 % fails |

Reference machine: Ryzen 5 3600 / 32 GB / Windows 11 (development machine) plus one low-end VM (4 GB RAM).

## 5. Security tests (release-blocking)

- Content-isolation probe (above) on every PR.
- IPC fuzzing: random/invalid arguments for every Tauri command must be rejected without panics. **M8:**
  - Wrong types are rejected by Tauri's deserialization before a command runs.
  - The checks behind every string argument are fuzzed: address-bar input, search templates, site names (the commands' `site_name` composition), custom DoH servers, protection values (`settings_file`, `user_input`).
  - Sending random messages into the running app's IPC channel is not done.
- **Fuzzing campaign (M8, D-050):** `fuzz/` (cargo-fuzz/libFuzzer, nightly, its own workspace).
  - **Running it:** `powershell -File fuzz/campaign.ps1` runs every target in parallel; `fuzz/seed.py` writes the seed corpora.
  - **No AddressSanitizer:** this Visual Studio has no AddressSanitizer runtime, so the targets run with `--sanitizer none`. `fuzz/sancov_win_sections.c` supplies the coverage-section boundaries libFuzzer needs on Windows. Coverage and the counter/PC tables were checked (1,378 = 1,378 for `proxy_head`). The targeted code is safe Rust.
  - **Results of a 15-minute parallel run per target (2026-11-24):**

  | Target | What | Runs | Coverage | Result |
  |---|---|---|---|---|
  | `proxy_head` | proxy request heads, forwarded-head invariants | 39,156 to the finding | 420 | **Finding:** a lone CR or LF inside a header line (or request path) was forwarded to the server: header smuggling. Fixed in `http::parse` (bare CR/LF and request-line tabs refused), regression cases added |
  | `proxy_head`, after the fix | the same | 23,745,972 | 547 | none |
  | `web_urls` | navigation policy, app links, download risk, parameter removal, local-address rules, audit scrubbing | 1,169,538 | 5,889 | none |
  | `settings_file` | settings file: parse, validate, repair invariants | 7,127,131 | 1,523 | none |
  | `block_list` | downloaded list validation, headers, host lists | 1,400,231 | 2,085 | none |
  | `cosmetic_rules` | hiding rules, selector safety (no `{`, `}`, `/*` in generated CSS), scripts | 713,895 | 1,987 | none |
  | `user_input` | address bar, search templates, site names, custom DoH (settings and network layer agree) | 838,459 | 6,435 | none |
  | `request_match` | request matching against the bundled lists | 844,456 | 7,991 | none |
  | `bookmarks_file` (D-055, 2026-11-25, 3 min) | imported bookmarks files and a tampered `bookmarks.json`: stored invariants, stable validation, export → import round trip | 70,219 to the finding | 2,510 | **Finding:** a title cut at 300 characters could end in a space, so validating it again changed it. Harmless, but not stable. Fixed in `clean_title` (trim after the cut), regression case added |
  | `bookmarks_file`, after the fix (5 min) | the same | 699,118 | 3,194 | none |
  | `block_list` with D-057 (3 min, 2026-11-26) | adds uBlock Origin's `!#if` preprocessing and the pop-up rule rewriting of downloaded lists | 900,929 | 2,291 | none |
- UI navigation lock: attempts to navigate the UI view to remote URLs fail.
- Proxy: unauthenticated connections rejected; malformed requests do not crash; no connection accepted from non-loopback. **M5:** unit tests (`untrace-net`: 407 without or with wrong credentials, malformed heads → 400, 200,000 mutated heads per run without a panic and with the forwarding invariants intact, plain HTTP forwarded without proxy headers, backstop, rebinding guard, paused proxy closes connections) and self-check 39. The listener binds `127.0.0.1` only. Coverage-guided fuzzing is part of the M8 campaign.
- Update: tampered manifest or bad signature → update refused. **M9:**
  - Self-check 56 runs the updater's own verification offline: correctly signed → accepted; changed by one bit, signed with a foreign key, or signed for another version → refused.
  - The release checklist (RELEASING.md) installs a test release and lets it update itself from a local address.
- Lists: oversized, truncated, garbage and "rules dropped by 90 %" lists → rejected, last-known-good kept.
- Config: corrupted/tampered settings → defaults + notice + audit entry.
- No system writes: run the app and integration suite while monitoring registry writes outside `HKCU\Software\UNTRACE` (if any) and file writes outside the data/install/download folders (Process Monitor capture in release checklist).
- `cargo deny`, `cargo audit`, `npm audit` clean (or documented exceptions).

## 6. Privacy leak checks (per milestone and release)

1. **Outbound inventory:** idle app for 10 minutes with no tabs → list every connection (network-layer connection view + OS tool). Every UNTRACE-initiated connection must be documented; runtime connections are listed in SECURITY §6.
2. **DNS leak:** with Strict DoH, browse fixture + 10 real sites with net-logging enabled (test build); the net-log must contain no host-resolver jobs or DNS transactions for those hosts. (The Windows DNS cache is not a valid detector: WebView2 uses Chromium's built-in DNS client, which bypasses it — S3.) **M5:** the fixture part is automated in the M5 probe (`spikes/harness m5`) with the real `untrace-net` proxy: page, image, fetch, WebSocket, `dns-prefetch` and `preconnect` names (see `spikes/m5-network/RESULTS.md`). The 10 real sites wait for the corpus run.
3. **Disk residue:** after a temporary session, search the data folders for fixture marker strings (cookies, localStorage, cache entries). **M4:** automated as self-check 35 (cookie, local storage and IndexedDB markers; positive control from a normal tab must be found). Cookie values are encrypted at rest, so the cookie marker is only ever found in memory, never on disk (S5). Finding from the M4 probe: after every engine delete function, the engine's `Preferences` still lists visited origins under `site_engagement`. UNTRACE now empties that list at every start (D-039). The probe verifies it on a real engine folder: no file names the site afterwards, and the engine restarts and loads pages. Unit tests in `engine_files.rs` cover the edit itself.
4. **Audit log:** grep for URLs/hostnames from the test run — must find none.
5. **Security report (M7):** the saved report must contain no host name contacted and no mention of the user's profile folder (the user name). Unit tests `report_escapes_and_leaves_browsing_out` and `the_profile_folder_is_masked_everywhere` (a planted host, and the real profile path in a check's detail, the data folder and a log entry). The hands-on check of 2026-11-23 found the profile path in a check's detail; it is fixed and now covered.

## 7. Real-world compatibility corpus

A fixed list of ~50 popular, diverse sites (news, video, banking-like login flows, maps, web apps) checked manually per milestone for breakage, with results recorded (site, protection settings, broken?, cause, exception needed?). Breakage is fixed by exceptions or rule changes — **never by weakening a default silently**.

## 8. CI

- Windows runner (WebView2 present): `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, integration suite, UI type-check + tests, `cargo deny`, `cargo audit`, `npm audit`.
- Nightly: fuzzing, performance corpus.
- Release: full manual checklist (RELEASING.md), privacy leak checks, signed-build verification. `scripts/release.ps1` runs the full check before it builds anything.

**Ad check on real sites (D-057, 2026-11-26):** `cargo run --release -p untrace-webview --example compat -- adcheck <out> <data> <url>…` loads each address in a host configured as UNTRACE ships, clicks the page three times through DevTools input (a real user gesture), and records pop-up tabs, the page's third-party requests and frames, YouTube's player ad data and screenshots.

| Site | Before (1.1.0) | After (D-057) |
|---|---|---|
| `9anime.es` | Fake captcha in an invisible full-page frame; 2 of 3 clicks opened ad tabs (adult site, casino); the ad network's scripts loaded | No captcha, no overlay frame, no pop-up tab; the ad scripts blocked; episode pages play |
| YouTube (a music video) | `adPlacements` 1, `adSlots` 2–3, `playerAds` 1; a "Sponsrad" ad played before the video | All 0, no ad shown; the video plays |

## 9. Self-check (implemented in M1)

`untrace.exe --self-check <report.json>` starts the real application in `<data root>\self-check` (never the user's profile), waits for the engine and the UI, and verifies:

| # | Check | Method |
|---|---|---|
| 1 | Engine and UI ready | First tab created, UI reported its content area |
| 2 | Content views carry no Tauri globals | Script in a local probe page (`https://selfcheck.untrace.invalid`, folder-mapped, no network) |
| 3–9 | Not elevated · settings valid · no host bridge · no password saving/autofill · SmartScreen off · crash reports local · history cleared at start | Read back from the engine (the same checks Diagnostics shows) |
| 10 | Developer tools read back as off | Protection registry `observe` |
| 11 | UI view cannot navigate away | Script in the UI view navigates to an unroutable host; the navigation lock must refuse it |
| 12 | Content visible in its area, UI not covered | Window capture (PrintWindow): page pixel at the content centre, UI pixel in the toolbar |

**Milestone 2 additions** (no network):

| # | Check | Method |
|---|---|---|
| 13–16 | Engine version supported · engine up to date · HTTPS-only on · UNTRACE error pages in use | Engine read-back (Diagnostics checks) |
| 17 | HTTPS-only upgrades `http://` and explains failures | Navigate to `http://https-only.untrace.invalid/check`: the https attempt fails and UNTRACE's panel offers the http address |
| 18 | Links to local files are blocked | `file:///C:/Windows/win.ini` → cancelled, counted, page unchanged |
| 19 | Abused application links are refused without asking | Page sets `location.href = 'ms-settings:privacy'` → refused, no prompt |
| 20 | Permission requests are asked about; a refusal reaches the page | Page requests location → prompt appears → "Block" → page's error callback gets code 1 |
| 21 | Downloads ask first and flag programs | Page downloads `untrace-check.exe` from a blob → prompt with `runs_code` → cancelled |
| 22 | Remembered decisions are saved, listed and can be reset | Location request → "Block" with "Remember for this site" → the profile lists `https://selfcheck.untrace.invalid` (the exact origin form the site panel matches) as blocked → Reset → gone |
| 23 | Accepted downloads are saved and marked as from the internet | Second automatic download from the page → the engine first asks "download several files" (allowed once) → download prompt → Save → completed, file exists, `Zone.Identifier` has `ZoneId=3` and the page as `HostUrl`. In self-check mode only, the Windows save dialog is replaced by a fixed folder (`set_test_download_dir`) |
| 24 | Certificate errors are refused and explained | Navigate to the HTTPS fixture (self-signed, issued for another name) → UNTRACE's certificate panel with the certificate's subject, counted as refused |

**HTTPS fixture.** `crates/untrace-webview/examples/tls_fixture.rs` (test tooling; `rcgen` and `rustls` are dev-dependencies and never linked into UNTRACE) serves a fresh self-signed certificate for `untrace-selfcheck-fixture.invalid` on `127.0.0.1:<random port>` and exits after a time limit. Nothing is added to any trust store. `scripts/check.ps1` starts it and passes `UNTRACE_SELFCHECK_TLS_URL` to the self-check. Run without it, check 24 is reported in `skipped`, not as passed, and `check.ps1` treats a skipped check as a failure.

**Manual M2 checks** (things the self-check cannot click: native dialogs, real sites, other applications):
- Certificate panel: open `https://expired.badssl.com/` and `https://wrong.host.badssl.com/`. Expect "This connection is not secure", the specific reason and certificate details, and no way to continue. *Done 2026-11-21.*
- Save… → Windows save dialog → download completes → file has a `Zone.Identifier` stream. *Done 2026-11-22:* a blob download from `http://127.0.0.1` (Internet zone) was saved through the dialog with `ZoneId=3`, `ReferrerUrl` and `HostUrl`. The same download from `http://localhost` (intranet zone) has no mark; that is Windows' zone policy, now stated in the downloads panel. Both appeared in the downloads panel as Done.
- External application: "Don't open" on a `mailto:` link. *Done 2026-11-22:* the question named the page and target, "Don't open" was the default button, and no mail client started. The "Open" path launches the user's mail client, so it is left to a person.
- Site panel on a real HTTPS site shows protocol, cipher and certificate from the engine. *Done 2026-11-22* on `https://example.com/`, with developer tools off: QUIC · X25519MLKEM768 · AES_128_GCM; issued to example.com by Cloudflare TLS Issuing ECC CA 3; valid until 2026-12-25.

Exit code 0 = all passed. The result is also recorded in the audit log. `scripts/check.ps1` runs it after every release build.

**Milestone 3 additions** (no network). Each list has a canary host under `canary.untrace.invalid` that can never resolve. A request UNTRACE blocks is answered by UNTRACE, so `fetch(…, {mode: 'no-cors'})` resolves. A request it lets through fails name resolution, so the fetch rejects. The page's own view of what happened is therefore checked, not just UNTRACE's counters.

| # | Check | Method |
|---|---|---|
| 25 | Request filtering registered | Diagnostics read-back (listed with the other read-backs, 3–16, in the report): every tab registered; worker requests assigned to one tab |
| 26 | Every block list is loaded and verified | Each list's Settings read-back (`filter_state`) matches its canary |
| 27 | Requests to listed hosts are blocked and counted, others untouched | Page fetches the ads, tracker, malware and phishing canaries plus an unlisted control: four answered, control fails; counters 2 requests + 2 threats; hosts listed |
| 28 | Requests from workers are blocked too | A shared worker fetches the tracker canary: answered; the session's worker counter rises by exactly 1 |
| 29 | Malware sites are replaced by a warning; continuing lasts the session | Navigate to the malware canary → `threat` panel naming URLhaus → "Continue anyway" → the page now fails to resolve instead (let through); later, inside another page, that host is still let through while phishing stays blocked |
| 30 | Phishing sites are replaced by a warning naming the list | `login.phishing.canary…` (a subdomain of a listed host) → `threat` panel, list "Phishing domains" |
| 31 | Switching a list off stops it, verified; on restores it | Settings change of "Block ads" (validate → apply → read back → save): outcome `verified`, ads canary now fails (let through) while trackers stay blocked; on again → blocked |
| 32 | A site exception stops ad/tracker blocking there, not malware/phishing blocking | Exception for the probe page's site: ads and tracker canaries let through, phishing canary still blocked |

Milestone 4 (privacy controls), still offline:

| # | Check | Method |
|---|---|---|
| 33 | Tracking prevention reads back as configured; changes are verified | Read-back is `balanced`; Settings change to `strict` → outcome `verified` and read-back `strict`; back to `balanced`, verified |
| 34 | Tracking parameters are removed before the request leaves | Open `https://params.canary.untrace.invalid/landing?utm_source=…&keep=1&fbclid=…` (never resolves): UNTRACE's error panel names `…/landing?keep=1` as the address requested, so the cleaning happened before any lookup; the tab counts 2 and names both. Switched off (verified) → the panel names the full tracked address; on again. Pages served from a mapped local folder (like the probe page) bypass the request event, so they keep their parameters; recorded for information |
| 35 | Temporary tabs are isolated and leave nothing on disk | A temporary tab stores a unique marker as a cookie, in local storage and in IndexedDB; a normal tab sees none of it; the temporary profile's tracking level reads back; after the tab closes no file in the content data folder contains the marker. Positive control: the same page in a normal tab writes another marker, which must be found on disk (otherwise the scan proves nothing). The scan runs while the engine is open, so files it holds locked (about 30) are counted as unreadable; the M4 probe repeated the scan after closing the engine, with no locked files, and found no temporary marker either |
| 36 | A site's cookies and storage are listed, deleted and read back as gone | The probe site is listed with ≥ 1 cookie → delete → engine reports 0 left → the page no longer sees its cookie or local storage |
| 37 | Deleting all cookies and site data leaves none | Marker stored again → "Delete all" (site data) → the engine lists no site with cookies |

Milestone 5 (network layer and DNS), still offline. The self-check profile runs with the defaults, so Encrypted DNS is Automatic and the network layer is on. Canary names (`*.untrace.invalid`) are never resolved: the proxy refuses them by name. The self-check's own test names are answered from a table that only the self-check fills. Two read-backs join the Diagnostics group: "Engine traffic goes through the network layer" and "Local-network protection on".

| # | Check | Method |
|---|---|---|
| 38 | The engine's requests reach the network layer with this launch's credentials | Start-up check `passed`; the engine's arguments are exactly the proxy's; Settings reads Encrypted DNS back as verified. The hosts the runtime asked for without credentials are recorded |
| 39 | The network layer refuses anyone without this launch's credentials | Raw `CONNECT` from the self-check thread without, and with wrong, credentials → `407` both; no connection made |
| 40 | The network layer blocks malware/phishing hosts the page check cannot see | The probe page makes one ordinary request (the engine answers the proxy's challenge for requests, not for WebSockets, and keeps the credentials per site; real pages always load over the network first), then opens WebSockets to the phishing canary and to a control test name (WebSockets never reach the request layer) → the proxy records both arriving with credentials; the canary is refused by the backstop, the control by the rebinding guard. Not the malware canary: check 29 continued to it for the session, which the network layer honours |
| 41 | Parts of public sites cannot reach this computer unless the site is allowed | A local listener stands in for a device. The probe page (a public site) fetches `http://127.0.0.1:<port>/` → blocked: the listener receives nothing, the tab counts 1 and lists the host as local → site allowed → the listener receives the request; read-back verified |
| 42 | Public names that point into this computer are refused (DNS rebinding) | A test name answering `127.0.0.1` → fetch from the probe page fails, the listener receives nothing, the proxy records the refusal → with the site allowed (the request layer announces the name) the listener receives it |
| 43 | Navigations UNTRACE cancels send nothing (HTTPS-only upgrade) | Navigate to `http://plain.selfcheck.invalid:<port>/leak?secret=1` (a test name answering `127.0.0.1`): the network layer must record no plain-HTTP request for that name, while the upgraded `https://` attempt does arrive (the control that the name was watched). Found in M5: the engine sends a cancelled navigation's request unless UNTRACE answers it (`spikes/m5-network/RESULTS.md`) |
| 44 | With the network layer stopped, nothing loads and nothing goes direct | The proxy closes every connection unanswered (self-check switch) → a fetch the request layer allows fails and the listener receives nothing → resumed: the same fetch reaches the listener once |

Milestone 6 (element hiding), still offline. The test pages are served from the self-check folder under two host names. Both carry a strict CSP: no inline script or style, frames only from the second host.

| # | Check | Method |
|---|---|---|
| 45 | The space blocked ads leave is hidden, in strict-CSP pages and cross-origin frames | `cosmetic.html` on `selfcheck.untrace.invalid` has four elements: the EasyList generic canary, the site-specific canary (filed under `untrace.invalid`), a real EasyList rule (`##.ad--banner`) and a control. The first three must compute to `display: none` and the control must not. Its frame on `cframe.untrace.invalid` reports its own canary element as hidden. Settings reads the switch back as verified |
| 46 | Hiding follows its switch and the per-site switch | Switch off (verified) → after reloading, all four elements and the frame's are shown. On again → hidden. A site exception for `untrace.invalid` → shown. Exception removed → hidden |

Milestone 7 (every protection has a self-check), still offline. `selfcheck::COVERAGE` maps each Settings protection to the checks that exercise it, and a unit test fails if one has none. Each report lists the result per protection: passed, failed, partly run or not run.

| # | Check | Method |
|---|---|---|
| 51 | Block lists are only updated while their switch is on | Switch off (verified) → one round of the background updater makes no attempt (its run counter is unchanged) → on again (verified). No update runs here: the self-check never goes online |
| 52 | Closing UNTRACE deletes what its switches say, checked | The page stores a marker as a cookie and in local storage. The routine that runs when the window closes then runs without closing, with cache and site data: it reports "done" with 0 cookies left (read back), and the page no longer sees the marker |
| 53 | The Strict provider reads back as not in use outside Strict mode | With Encrypted DNS on Automatic, choosing Cloudflare is saved with outcome *unverified* and the reason "Used only when Encrypted DNS is set to Strict"; the same for going back to Quad9 |
| 54 | WebRTC stays inside the network layer (M8, D-052) | A UDP stand-in on this computer's LAN address plays the STUN server. It must receive a test datagram from the check itself (or a pass would prove nothing). Then a page in a normal tab and one in a temporary tab gather WebRTC candidates against it for 3 s. Both must run and nothing may arrive. Settings reads the switch back as verified. Reported as not run on a computer without a LAN address |
| 55 | Websites follow UNTRACE's light/dark choice when asked, and Windows otherwise (D-053) | Theme Dark with "Websites follow this theme": the page's `matchMedia('(prefers-color-scheme: dark)')` is true, `light` false, and the engine reads back Dark. Light: the reverse. Black with the switch off: the engine reads back Auto (Windows decides). Back to System afterwards |
| 58 | Ad pop-ups opened by a click are refused; other new windows open (D-057) | A test page opens one window per click (DevTools input, a real user gesture): to the pop-up canary (a built-in `$popup` rule), a blank window sent to the canary 300 ms later, and an ordinary page. The first two must be refused and counted, the third must open |
| 59 | The lists' scriptlets run before the page's own scripts (D-057) | A canary rule sets `window.untraceScriptletCanary` on the self-check host with uBlock Origin's `set` scriptlet. The page's first inline script must already see it, and it must still be there after load |
| 57 | A background tab sleeps, and wakes when opened (D-056) | A page starts a 50 ms timer. Asked to sleep while in view, the tab refuses. A new tab is opened, and the first tab, now in the background, is put to sleep: the engine reports it suspended (`IsSuspended`) and the interface shows it sleeping. Opening it again: the engine reports it awake, the interface no longer shows it sleeping, and the page's timer counts on. |
| 56 | UNTRACE updates are installed only with a valid signature for their version (M9, D-016) | With the switch off, one round of the update worker makes no check. The updater's own verification (the one that runs before an installer starts) is given a manifest for 99.0.0 and test signatures made with a throw-away key whose public half is in the check. It must accept the correctly signed payload, and refuse the same payload changed by one bit, a signature from a foreign key, and a signature made for 98.0.0 (no downgrade through a tampered manifest). Offline: the manifest is handed over directly, nothing is requested |

**From the app (M7, D-046):** Diagnostics › Run self-check starts this same self-check in a separate test instance and shows the report per protection; Settings shows each protection's last self-test.

**Test pages (2026-11-24):** the self-check's pages are answered by UNTRACE's own request handler from the self-check folder (`ContentHost::map_folder`), before anything reaches the network. They used to be served by WebView2's virtual-host mapping. From runtime 158 (an Evergreen update during this work), behind an authenticated proxy, the engine first sends such a navigation through the proxy, reports it failed, then loads it again. UNTRACE's error page took over that first failure, and 13 checks failed until the change. The behaviour was measured with `spikes/harness m8 vhost`: bare, behind the proxy and behind the authenticated proxy, with a reserved and an ordinary name, and with `msWebView2HostResourceAccessHardening` off. Browsing is not affected: only the self-check uses mapped folders.

Downloading and validating real lists is covered by unit tests in `untrace-filter` (wrong list, HTML error page, truncation, binary, oversize, shrinkage, garbage) and checked by hand against the real list hosts (TESTING §7 run, 2026-11-22). The self-check never starts the updater.

**Clean exit** (in `scripts/check.ps1`, after the self-check): starts the real app in an isolated data folder and closes its window. It requires exit code 0 within 10 s and no WebView2 processes left for that folder, and (M4) that the cache was deleted on close (`config/exit-clear.json` records `done`). The self-check cannot cover this, because it exits through a different path (`app.exit`). Added after M2 found the app hanging in `ExitProcess`.