# UNTRACE — Roadmap

Small, verifiable milestones. Each milestone has an exit gate: its tests (TESTING.md) pass, documents are updated, and the threat model is re-checked. **No milestone starts before the previous gate is passed and reviewed.**

Estimates assume one developer and are deliberately rough; they are revised after M0.

---

## M0 — Feasibility spikes · **done 2026-11-21** · *no product code*

Result: architecture confirmed with the changes recorded in DECISIONS.md (D-002 container window, D-010 no "block all", D-015 vehicle a3, D-024 native DoH). Details: `spikes/M0-RESULTS.md`. Carried forward:
- real-site overhead corpus (needs approval to visit real sites);
- manual DPI/IME/focus checks (M1);
- single-environment experiment (M1);
- cosmetic data budget (M6).

Throwaway code in `spikes/`. Results recorded in DECISIONS.md (status → Accepted / changed).

| Spike | Work | Gate |
|---|---|---|
| **S1 Shell & composition** | Tauri window + UI view; second WebView2 environment created via `webview2-com`; content controller as child HWND; resize, DPI change, z-order, focus hand-off, Ctrl+L/T/W while content focused, IME; measure memory with 1 vs 2 environments; probe page checks content globals | All interactions work; no Tauri/host globals in content; memory recorded → D-002, D-003 |
| **S2 Interception** | `AddWebResourceRequestedFilterWithRequestSourceKinds` on runtime 157; coverage fixture (main, same-/cross-origin iframe, dedicated/shared/service worker, fetch, XHR, beacon, WebSocket, prefetch, fonts, CSS imports); adblock-rust match timing; 50-site load overhead vs. bare; optional uBO Lite comparison | Coverage table; overhead ≤ 10 % p95 → D-004, D-005 |
| **S3 Proxy & DNS** | Minimal CONNECT proxy with auth via `BasicAuthenticationRequested`; `--proxy-server` honoured for all page traffic?; proxy-down behaviour; DNS leak check; Windows native DoH query API vs. `hickory-resolver`; list runtime background connections | No leak; fails closed → D-006, D-023 |
| **S4 Cosmetic vehicle** | Prototype vehicles (a), (b), (c) on CSP-strict page, cross-origin frames, 20-site corpus | One vehicle passes → D-015 |
| **S5 Session & storage** | InPrivate residue; profile isolation; `ClearBrowsingData` kinds incl. history; Mark-of-the-Web on downloads; custom crash reporting location | Pass/fail per item → D-014 |
| **S6 Third-party cookies** | `Network.setCookieControls` across navigations, cross-origin frames, new views, restart | → D-010 |

**Exit:** feasibility addendum + updated DECISIONS.md reviewed by the product owner, including the open decisions (D-012, D-016, D-017, D-018, D-019, D-023). Go / no-go on the architecture.

---

## M1 — Foundation · **core delivered 2026-11-21**

Delivered:
- workspace (core + webview crates, Tauri app, React UI);
- tabs and navigation;
- address field (URL vs. search, refused schemes, HTTPS by default for bare host names);
- UI navigation lock and CSP; content views without bridge;
- refuse-elevation; single instance;
- versioned, validated settings with apply/verify/revert;
- URL-free audit log;
- design system (dark/light/system);
- Settings, Diagnostics and site panel;
- `scripts/check.ps1` + CI workflow;
- `--self-check` (12 end-to-end checks, all passing).

Still open before the M1 gate:
- [ ] Manual checks on a real desktop: DPI change between monitors, IME input, mouse focus hand-off between UI and page (M0/S1 carry-over).
- [x] Single-environment experiment (D-003): would save ~120 MB private memory, but Tauri cannot keep crash dumps local, so the dedicated environment stays (`spikes/m1-shared-env/RESULTS.md`).
- [x] Compatibility corpus: 53 real sites; 50 loaded on the first pass, 3 first-visit bot checks loaded on revisit, 0 failures caused by UNTRACE (`spikes/m1-compat/RESULTS.md`).
- [ ] Enable CI (needs a repository; pin actions to commit SHAs first) and run `cargo deny` / `cargo audit`.

Original scope:

- Cargo workspace + four crates + Tauri app + React UI skeleton; CI (fmt, clippy, tests, deny, audit).
- Content view manager: tabs, navigation (back/forward/reload/stop), address field (URL vs. search), titles, favicons, pop-ups as tabs, accelerators.
- Navigation lock + CSP for the UI view; content views without bridge; refuse-elevation; single instance.
- `untrace-core`: settings storage (versioned, atomic, validated), protection registry with apply/observe/revert, audit log.
- Design system tokens, dark/light themes, top bar, side panel, Settings and Diagnostics page shells.

**Exit:** content-isolation probe passes in CI; settings round-trip and tamper tests pass; basic browsing works on the compatibility corpus.

## M2 — Browser security baseline · **complete 2026-11-22** (gate approved by the product owner)

Delivered (policy in `untrace-core::policy`, 7 unit tests; behaviour in the self-check, now 24 checks):
- **UNTRACE error panels** drawn by the trusted UI while the page view is hidden (D-029): HTTPS unavailable, certificate refused (reason + issuer, subject, validity), load errors. The engine's own error pages are off.
- **HTTPS-only** (on by default, Settings toggle): upgrade, loop guard, loopback exempt, per-session "Continue over HTTP" (D-030).
- **Certificates** always refused (D-008). Checked against expired.badssl.com and wrong.host.badssl.com.
- **Scheme gate:** links to `file:` and internal browser pages are blocked with a notice.
- **Prompt bar** (above the page, never over it) for:
  - permissions: asked, or refused by policy, with "Remember for this site";
  - other applications: abused link types refused, others asked each time;
  - downloads: ask, then the Windows save dialog, programs flagged (D-031).
- **Site panel:** saved permissions with Reset, per-page counts of what was refused, and connection details for valid HTTPS pages (protocol, key exchange, cipher, certificate subject, issuer and expiry), read from the engine through the DevTools protocol's `Security` domain.
- **Downloads panel:** session-only list, with Show in folder and Cancel.
- **Engine checks:** minimum runtime version (130) enforced; "newer engine waiting" shown in Diagnostics.
- **Bugs found and fixed:**
  - App-link hand-offs (`mailto:`, `zoommtg:`) were treated as page loads (they could hide the page and stall permission prompts). Completions are now matched by navigation id.
  - Keyboard focus stayed in the hidden page view behind a panel. It now moves to the panel's main button.
  - **Closing the window never ended the process** (found in the hands-on pass). The last reference to the WebView2 environment sat in a thread-local, so it was released inside `ExitProcess`. There WebView2 waits for engine threads Windows has already stopped. The process stayed stuck with one thread, refused `TerminateProcess`, locked `untrace.exe`, and left both engine processes running. The stack (taken with a dbghelp walker) showed `ExitProcess → tls_callback → Rc::drop_slow → EmbeddedBrowserWebView → WaitForSingleObject`. The host is now released when the window is destroyed. Closing exits with code 0 in about 0.1 s, and `scripts/check.ps1` checks it.
  - Saved permissions never appeared in the site panel: the engine reports origins as `https://site/`, the panel matched `https://site`. Origins are now normalised when read; self-check 22 asserts the exact form.
  - The downloads panel said every download is marked as from the internet. Windows does not mark files from `localhost` or the local network, so the text now says so (D-031).
  - Download and external-app questions for `blob:` links said "This page" or showed a trailing slash. They now name the page's origin like other questions.

Closed 2026-11-22 (were open before the gate):
- [x] Certificate details for valid connections in the site panel (DevTools protocol `Security` domain). Checked on example.com with developer tools off.
- [x] Automated certificate-error test: self-check 24 against a local HTTPS fixture with a self-signed certificate (`examples/tls_fixture.rs`; test-only dev-dependencies, no trust-store changes).
- [x] "Remember for this site" → listed → Reset: self-check 22.
- [x] Accepted download saved with Mark-of-the-Web: self-check 23, plus the real Windows save dialog by hand (TESTING §9).
- [x] "Don't open" for an external application, by hand.

Left to a person (not automated, by design):
- [ ] "Open" for an external application: it launches the user's own mail client or other app.

Original scope:

- HTTPS-only with failure page and per-site/session HTTP continuation.
- Certificate errors: always cancel, explained error page, certificate details (DevTools protocol for valid certificates).
- Scheme gate + external-scheme prompts.
- Permission manager (ask/deny defaults, side-panel per site, read-back, reset).
- Download manager (ask location, executable warning, MOTW per S5).
- Content settings hardening (§4.3 ARCHITECTURE), crash dumps local.
- Diagnostics: engine version, minimum-version check, configuration checks.

**Exit:** TESTING §3 rows for HTTPS, certificates, permissions, downloads, external schemes pass.

## M3 — Network filtering · **complete 2026-11-22** (gate: proceed to M4 approved by the product owner once the paired run passed)

Decisions: D-032 (lists and defaults), D-033 (warning with session-only "Continue anyway"), D-034 (worker owner tab, 403 responses).

Delivered:
- **`untrace-filter` crate** (18 unit tests): catalog of four lists with bundled snapshots (EasyList, EasyPrivacy, URLhaus malware domains, phishing domains); validation of downloads; list store with previous copy and checksums; one adblock-rust engine for ads/trackers (network rules); host sets for malware/phishing; per-list canaries; verified engine cache.
- **Request filtering in every tab** (documents' requests incl. frames) plus worker requests through one owner tab. Blocked requests get an empty 403.
- **Malware/phishing warning panel** before any connection, naming the list; "Continue anyway" for the host until UNTRACE closes.
- **Settings:** Block ads, Block trackers, Warn about malware sites, Warn about phishing sites, Update block lists automatically. Each is read back; the lists via their canaries.
- **Site panel:** ads/trackers blocked on this page, threats blocked, blocked hosts with counts, and a per-site "Block ads and trackers" switch saved in Settings (malware/phishing warnings stay on).
- **Updates:** WinHTTP (HTTPS only, TLS 1.2+, no cookies). A list is downloaded when its `Expires` says so (12 h / 4 days), validated, stored with the previous copy, and swapped in only after the engine cache is rebuilt and verified. "Check for new versions" and a status per list in Diagnostics. Verified against the real hosts: EasyList/EasyPrivacy updated (09:45 → 10:16 versions), unchanged lists recorded as checked.
- **Measured** (release, bundled lists): engine build 70 ms, cache 4.8 MB loading and verifying in 2.1 ms, threat sets 7 ms, matching p50 5.1 µs / p99 6.8 µs per request.
- **Self-check:** 32 checks (8 new, all offline via canary hosts). Real-site run: 51/53 loaded; both failures are first-visit bot checks that also occur without lists (`spikes/m3-filtering/RESULTS.md`).
- **Licence notice** for the bundled lists (`crates/untrace-filter/lists/NOTICE.md`); none needs D-017.

Closed:
- [x] **Paired overhead measurement** for the TESTING §4 budget "≤ 10 % p95": met. 143 alternating off/on pairs in fresh profiles: p95 −0.1 % (host-timed) / −0.5 % (page load event). An apparent vimeo.com slowdown did not repeat in five further pairs (`spikes/m3-filtering/RESULTS.md`).

Still open (not blocking):
- [ ] Terms of the OpenPhish and PhishTank sources behind the phishing list (D-032) — before the first public release.

Deferred by design (documented): redirect resources and scriptlets (M6, D-017); hiding the space blocked ads leave (M6); WebSocket filtering (M5 network layer); worker requests counted per session, not per page (D-034).

**Exit:** blocking/exception/interstitial tests pass; performance budget met; list-validation security tests pass.

## M4 — Privacy controls · **complete 2026-11-22** (gate approved by the product owner)

Decisions: D-035 (tracking prevention Balanced), D-036 (temporary tabs, shared session), D-037 (no per-tab third-party cookie deletion), all by the product owner; D-027 and D-038 (technical); D-039 (remove the engine's engagement records at start-up), by the product owner.

Delivered:
- **Tracking prevention** (Settings › Privacy): Off/Basic/Balanced/Strict, default Balanced. Set on every engine profile and read back from each.
- **Tracking parameters removed** before the request leaves: ~50 names plus every `utm_*`, and four share parameters on their own sites only. A page or frame GET request is answered with a redirect to the cleaned address. The site panel names what was removed. Verified against a local fixture: the server never sees them, including after a server redirect and in frames; form POSTs are untouched (`spikes/m4-privacy/RESULTS.md`).
- **Temporary tabs** (Ctrl+Shift+N or the dashed button): one shared InPrivate session with a random profile name, marked by a dashed outline, icon and label. Pop-ups stay temporary; per-site choices made there are never saved. Leftover profile folders are removed at the next start.
- **Cookies and site data:**
  - The site panel shows the site's cookies with a Delete button (cookies plus local storage, IndexedDB and service workers), read back afterwards.
  - The data page lists every site with cookies and has "Delete all".
- **Clearing on exit:** "Delete the cache when UNTRACE closes" (on) and "Delete cookies and site data when UNTRACE closes" (off). Closing waits for the engine, at most 10 s, then checks that no cookie is left. A session that could not finish is cleared at the next start before any page loads. Diagnostics shows the last result.
- **Your data page** (Settings › Your data):
  - Each category: what it is, where, its size on disk, how long it is kept, and a button to delete it now.
  - Categories: cookies and site data, cache, engine history, saved permissions, settings and blocking exceptions, activity log, crash reports, block lists, engine files, memory-only data.
  - Crash reports older than 7 days are now deleted at start (D-013).
- **Third-party cookies** per D-010/D-037: restricted for known trackers through tracking prevention and EasyPrivacy; no "block all" and no per-tab deletion.
- **Self-check:** 37 checks (5 new, offline):
  - tracking prevention read-back and change;
  - parameter removal;
  - temporary-tab isolation and **disk residue with a positive control** (TESTING §6.3);
  - per-site deletion;
  - "Delete all".
  The clean-exit step now also requires the cache to have been deleted on close.

Open:
- [x] **D-039:** the engine's per-site "engagement" records (visited origins) survive all of its delete functions. UNTRACE now removes them at every start, before the engine runs, together with the engine's record of temporary profiles. That record had made the engine recreate a removed temporary folder at the next start. Verified by unit tests and on a real engine folder (`spikes/m4-privacy/probe-engine-file-cleanup.json`).
- [ ] Manual pass on a real desktop of the site panel's Delete on a real site (temporary-tab marking, data page and clearing on exit were checked by hand on 2026-11-22). Not blocking.

**Exit:** privacy-leak check §6.3 (disk residue) passes; read-backs verified.

## M5 — Network layer & DNS · **complete 2026-11-23** (gate: proceed to M6 approved by the product owner once the real-site run passed; S3 passed)

Decisions: D-040 (local-network protection), D-041 (Strict providers), D-042 (backstop: malware and phishing only), all by the product owner; D-006, D-023, D-025 and D-026 implemented.

Pre-check S7 (`spikes/m5-network/RESULTS.md`):
- WebView2 applies no local-network protection at all; the engine reports "Allow" for every public-to-local request.
- Through a loopback proxy, Chromium classes every page as "Loopback".
- Both findings led to D-040.

Delivered:
- **`untrace-net` crate**, with no new dependencies. Its unit tests include a 200,000-input randomised parser test, which found one parser bug that is now fixed.
  - Loopback proxy with per-launch credentials and a random realm.
  - CONNECT tunnels and one-shot plain-HTTP forwarding.
  - Name resolution through `DnsQueryEx`, over HTTPS where possible.
  - Local-address rules.
  - Read-only DNS diagnostics.
- **Encrypted DNS** (Settings › Network): Off / Automatic (default) / Strict. It takes effect at restart.
  - Strict offers Quad9, Cloudflare, Mullvad, or your own server. Changing the provider applies at once.
  - All three providers answer over DNS over HTTPS on IPv4 and IPv6. A wrong DoH path fails, so there is no silent plain-DNS fallback.
  - On this machine, Automatic uses the Windows resolver, because the DNS server (192.168.1.26) has no known encrypted address. Diagnostics says so.
- **Start-up check:** before the first page loads, a request from the engine must reach the proxy with this launch's credentials. This also absorbs the proxy's one-time challenge (D-026). If the proxy cannot start, no page opens.
- **Backstop:** malware/phishing hosts are refused at the network layer, WebSockets included. "Continue anyway" is honoured.
- **Runtime background traffic** (no credentials) is refused, and its hosts are listed in Diagnostics (D-025).
- **Local-network protection** (Settings › Security, on by default):
  - Parts of public sites cannot reach this computer or the local network.
  - The site panel counts such attempts and can allow a site.
  - The DNS-rebinding guard works at the network layer.
- **Site panel:** a "Route" line saying whether the network layer saw the page's host and how its name was looked up. Error panels give the network layer's reason.
- **Diagnostics:** this computer's adapters and DNS servers, with Windows' encryption state (read-only); the resolver in words; counters; the hosts contacted this session (memory only, "Forget records"). Two new checks.
- **Data page:** network-layer records (memory only, forgettable).
- **Self-check:** 47 checks (9 new, offline):
  - credentials;
  - the start-up route check;
  - the backstop on a WebSocket;
  - local-network blocking and per-site allow;
  - the rebinding guard;
  - fail closed with the proxy not answering;
  - **a cancelled navigation sends nothing** (see below).
- **Fixed an M2/M3 flaw found by the M5 probe:** a navigation UNTRACE cancels still sent its request. Malware/phishing warnings let the page request reach the listed site, and HTTPS-only let the first request go out unencrypted. UNTRACE now answers those requests itself (D-009, D-033 notes; self-check 43).
- **DNS leak test** (TESTING §6.2, fixture part): the engine's net-log shows no resolver job, DNS transaction or system lookup at all while browsing through the network layer.

- **Exit criteria:**
  - DNS leak: the net-log shows no lookup by the engine.
  - Proxy security: unit tests plus self-checks 39 and 44.
  - Bypass shows *not verified*: in the M5 probe, an engine started without the proxy arguments never delivers the check request; unit tests cover the read-back.
- **Checks:** 79 unit tests (13 new in `untrace-net`, 2 in the app), self-check 47/47 with nothing skipped, and a clean exit with the network layer on. Hands-on in an isolated profile showed the new screens rendering as designed (2026-11-22):
  - Settings › Network: the restart-pending line and the custom-server form, which refuses `http://`;
  - the site panel's "Route" line;
  - Diagnostics' DNS section and connection view.

Open:
- [x] **Paired page-load overhead with the network layer on:** met. 101 pairs on the 53-site corpus, Automatic mode: p95 −18.5 % host-timed, −17.7 % load event; median −2.9 % / −4.7 %. This means no measurable overhead; part of the gain is Windows' warm DNS cache (`spikes/m5-network/RESULTS.md`). Strict mode not measured.
- [ ] UNTRACE's own list downloads use Windows networking directly, not the network layer, so their two host names are looked up by Windows even in Strict mode (documented; routing them through the proxy is a possible follow-up).
- [ ] Coverage-guided fuzzing of the proxy parser (M8 campaign; M5 has randomised tests).
- [ ] Terms of OpenPhish/PhishTank (from M3), before the first public release.

**Exit:** DNS-leak and proxy security tests pass; verified-state logic shows *not verified* when the proxy is bypassed.

## M6 — Cosmetic filtering · **complete 2026-11-23** (gate accepted by the product owner on the typical cost; p95 may be re-measured later) (vehicle per D-015)

Decisions: D-043 (scriptlets wait for D-017), D-044 (extended rules not applied), D-045 (own switch, on; generic rules by observation), all by the product owner.

Spike (`spikes/m6-cosmetic/RESULTS.md`):
- applying generic rules by observing classes and ids costs about 4.4 ms per document, mostly parsing the 0.84 MB script;
- applying all generic rules at once costs about 3 times as much;
- hiding is correct under a strict CSP and in cross-origin frames, with no CSP reports.

Built:
- **`untrace_filter::cosmetic`**: sorts the hiding rules (generic by class/id, other generic, site-specific, exceptions, `$generichide`/`$elemhide`); refuses selectors that could carry declarations; adds canaries; generates the script.
- **Host:** two scripts per tab. The generic rules (0.23 MB) are registered before the tab's first page. The visited site's own rules (about 1 KB) are registered when a top-level navigation starts, and applied again when content starts loading if that registration came late. Both are regenerated on list, switch or exception changes; the read-back uses the canaries and the registration on every tab.
- **Settings:** "Hide the space blocked ads leave" (Blocking, on); the per-site switch covers hiding. Diagnostics: rule counts and what is not applied.
- **Self-check:** 50 checks (45 and 46 new, plus the read-back "Ad space hidden in every tab"), all passing; clean exit passing.

Real-site measurement, hiding on vs off (`spikes/m6-cosmetic/RESULTS.md`):
- **First design (one 0.84 MB script per document):** load-event p95 +12.0 %, over budget. The spike then showed the cost is the script's size, so the site-specific rules were split out.
- **Split design:** +6 ms for 9 documents on the spike page, against +77 ms before. On real sites, the median of per-pair ratios is 1.039 host-timed and 1.072 by load event, a typical cost of about 4 %.
- **p95 not settled:** the network was much noisier than during M3/M5. The p95 swung between −0.3 % and +27.1 % across runs and measures (corpus + tail repeats: +7.8 % load event, +16.3 % host-timed). Single sites moved by seconds in both directions.
- No site was consistently slower once re-measured (open.spotify.com: 3 of 8 and 4 of 8 pairs slower).

Open:
- [x] Gate decision: accepted by the product owner (2026-11-23) on the ~4 % typical cost, with the p95 unsettled.
- [ ] Optional, later: re-measure the hiding p95 on a quieter network (`compat … paired-hide`, corpus plus tail repeats), with the product owner's go-ahead to visit the corpus again.

Deferred by design: scriptlets (D-043), extended rules (D-044).

**Exit:** cosmetic tests incl. CSP-strict and cross-origin frames pass; no regression in page-load budget. *Status: the tests pass; the budget is met by the typical (median) cost, not demonstrated by p95. Accepted by the product owner on that basis; a p95 re-measure stays possible.*

## M7 — Diagnostics & audit completion · **complete 2026-11-23** (gate approved by the product owner)

Decisions: D-046 (self-check from Diagnostics in a separate test instance), D-047 (HTML security report without browsing data), both by the product owner.

Built:
- **Self-check for every protection:**
  - `selfcheck::COVERAGE`, plus a unit test that fails if any protection in Settings has no self-check;
  - new checks 51–53: updates only while switched on, clearing on close, and the Strict provider's honest *not verified* path.
- **"Run self-check" in Diagnostics:** a second UNTRACE in its own window and test folder, offline; results per protection in Diagnostics and as a "Self-test" line under each protection in Settings.
- **Activity log page:** all entries, filter, export, clear.
- **"Save security report…":** HTML, no scripts, no browsing data.
- **Updates card:** engine, lists, the app itself (M9).

Verified (2026-11-23):
- **Full check:** 53 of 53 self-check steps pass (incl. 51–53), all 15 protections report *passed*, clean exit passes; 10 app and 32 core unit tests.
- **Hands-on, in an isolated data folder:**
  - "Run self-check" opened the separate "UNTRACE self-check" window; the result was 52 of 53 passed, 1 not run. The not-run check is the certificate check, which needs the developer check script's TLS fixture.
  - Diagnostics and Settings showed the per-protection results, and the activity log page listed and exported every entry.
- **Found and fixed during the hands-on check:**
  - The saved report masked the data folder but not a check's free-text detail, so the crash-report folder showed the Windows user name. The whole page is now masked: plain, JSON-escaped and HTML-escaped forms, in any case, with a unit test through the full report.
  - The finish note said "every check passed" while one check had not run; it now names the checks that did not run.

**Exit:** every registry protection has a working self-test and an honest *not verified* path. *Status: met. The coverage unit test passes, every protection's self-test passes, and an unverifiable state reads "not verified" (self-check 53 exercises it for the Strict provider).*

## M8 — Fingerprinting evaluation & hardening pass · **complete 2026-11-24** (gate approved by the product owner, including D-011)

Decisions: D-048 (baseline Chrome + bare WebView2), D-049 (remove WebView2 tells only where consistent), D-050 (coverage-guided fuzzing), D-051 (cargo-deny and cargo-audit), all by the product owner.

- Fingerprint test harness (local); measure identifiability (UA-CH brands, `chrome.webview`, etc.).
- Adopt only measures with demonstrated benefit and low breakage; document the rest as limitations.
- Full threat-model review; fuzzing campaign; dependency review.

Built and found (`spikes/m8-fingerprint/RESULTS.md`):
- **Fingerprint harness** (`spikes/harness m8`): one local page measured in the page, a fresh `about:blank` frame, same-origin and cross-site frames, and dedicated, shared and service workers, plus the request headers, in Chrome, bare WebView2 and UNTRACE.
  - **WebView2's tells:** the client-hint brand on every request, `chrome.webview`, no Payment Request API, only local speech voices, and an engine-set `DNT: 1` about 2.5 s after start.
  - **UNTRACE adds nothing a page can read**, and the fingerprint is stable across sessions.
  - **No measure passes D-049:** brand removal is inconsistent in workers, cross-site frames and headers; hiding `chrome.webview` is consistent but adds no privacy. D-011 updated with this evidence; nothing adopted.
- **High-severity finding, fixed (D-052):**
  - **The gap:** WebRTC went around the network layer, with UDP to devices on the local network and STUN names looked up with plain DNS, even in Strict mode.
  - **The fix:** "Keep WebRTC inside the network layer" (Settings › Network, on) writes the engine's `webrtc.ip_handling_policy` into every content profile before the engine loads it.
  - **Proof:** self-check 54, in a normal and a temporary tab.
- **Fuzzing** (D-050, `fuzz/`): 7 cargo-fuzz targets, 15 minutes each. One finding: the proxy forwarded a lone CR/LF inside a header line. It is fixed (`http::parse`), and the re-run was clean (23.7 M inputs). The other six targets found nothing (TESTING §5).
  - On Windows without the AddressSanitizer runtime, a small C shim supplies libFuzzer's coverage sections.
- **Dependency review** (D-051): cargo-deny and cargo-audit installed and run in every full check.
  - **Advisory fixed:** RUSTSEC-2026-0594 (`cookie` 0.18.2 → 0.18.3, via Tauri).
  - **Path dependencies:** allowed in `deny.toml`.
  - **Warnings left:** six, all for Linux-only crates.
- **Threat-model review:** every row checked. Rows added: WebRTC, vulnerable dependencies. Rows corrected: the non-existent cosmetic data host, DNS leaks (WebRTC), the proxy parser, IPC arguments, background traffic.
- **Self-check:** 55 items, all passing.

Open:
- [x] Gate approved by the product owner (2026-11-24), D-011 accepted.

Not done (documented):
- Randomised fingerprint defences ("farbling"), excluded by D-049.
- Fuzzing the running app's IPC channel itself.
- AddressSanitizer: not installed in this Visual Studio.
- A real-site check that video calls still connect through the network layer with D-052 on: needs the product owner's go-ahead to visit call services.

**Exit:** D-011 updated with evidence; no open high-severity findings. *Status: D-011 updated; the one high-severity finding (WebRTC) is fixed and verified; no other high-severity finding open.*

## Appearance · **built 2026-11-24** (between M8 and M9, D-053)

The product owner asked for a darker look and other colours.
- **Theme:** System, Light, Dark, Black.
- **Accent colour:** seven presets, contrast-checked by a unit test.
- **"Websites follow this theme":** the engine's supported colour-scheme setting, read back; self-check 55.
- The interface's look is not visible to websites.
- **Found along the way:** WebView2 Runtime 158 arrived as an Evergreen update during this work and broke the self-check's test pages (virtual-host mapping behind an authenticated proxy). They are now answered by UNTRACE's own request handler (TESTING §9). The full check passes on 158: 56 of 56.

## M9 — Packaging, updates, release · **complete 2026-11-25** (gate approved by the product owner; release 1.0.0 built the same day)

Decisions (product owner, 2026-11-25):
- **D-016:** GitHub Releases; unsigned until a certificate is bought.
- **D-017:** MPL-2.0.
- **D-018:** DuckDuckGo as the default search engine.
- **D-054:** checklist on this PC, not a clean VM.

- Per-user NSIS installer (WebView2 bootstrapper for machines without the runtime), Authenticode signing, Tauri updater with signed manifests, release process, SECURITY.md reporting channel, privacy notice in-app, first-run explanation screen (one screen, no tour).

Built (2026-11-25):
- **Repository and licence:** git repository on `main`, published at [MiniJohan/UNTRACE-Browser](https://github.com/MiniJohan/UNTRACE-Browser). `LICENSE` (MPL-2.0), with the licence field on every package.
  - Spike evidence had local profile paths with the user name; they are masked as `%USERPROFILE%` before the first commit.
- **Third-party notices:** `scripts/notices` generates `THIRD-PARTY-NOTICES.txt` from the shipped dependency graph (275 crates, 4 npm packages). It ships with the installer and in About; the full check fails if it is out of date.
- **Privacy notice:** `PRIVACY.md`, compiled into the app.
- **Welcome and About:** a one-screen welcome at the first start; Settings › About shows the version, the licence, the privacy notice and the notices.
- **Installer:** per-user NSIS, WebView2 bootstrapper embedded (6.5 MB). The uninstaller's "Delete the application data" option also removes `%LOCALAPPDATA%\UNTRACE`.
- **Updates:** Tauri updater with Windows TLS, daily while "Check for UNTRACE updates" is on. Shown, never auto-installed. Ed25519 signature bound to the version (`requireSignedVersion`). Self-check 56. Set up with the product owner's release key and the GitHub release address (2026-11-25).
- **Release process:** `scripts/release.ps1` and `RELEASING.md`: one-time setup, steps and checklist. SECURITY.md names GitHub's private vulnerability reporting.
- **Found and fixed:**
  - Tauri's per-user install folder equals UNTRACE's data folder. They now share it by design: program files at the top, data in subfolders, and UNTRACE never deletes the whole folder (ARCHITECTURE §8).
  - The activity page said "about 2 MB"; the log holds about 1 MB.
  - The update confirmation's layout, and a list rendering in the privacy notice.

Release checklist on this PC (D-054), 2026-11-25:
- [x] **Install:** silent install of a 0.1.0 test release without administrator rights; Apps entry "UNTRACE 0.1.0" for the current user.
- [x] **First start:** the welcome screen once; About shows the version, the engine, MPL-2.0 and the privacy notice.
- [x] **Update:** Diagnostics › Check now found 0.2.0 at a local test address (a throw-away key, test-only configuration); "Install and restart" downloaded it, verified it and installed it, and UNTRACE restarted as 0.2.0 with its settings and data kept. Activity log: available → downloaded and verified → 0.2.0 started, 4 s.
- [x] **Uninstall (keeping data):** program files, Apps entry and Start-menu shortcut removed; all data folders kept.
- [ ] **Uninstall with "Delete the application data":** not run, because it would delete the real data folder on this PC. The hook is verified in the generated installer script only.
- [ ] **Clean machine:** no WebView2 Runtime, no development tools. Open until a public release (D-054).

Release setup (product owner):
- [x] GitHub repository created; private vulnerability reporting on (2026-11-25).
- [x] Update key generated and kept outside the repository; its public key and the release address are in `tauri.conf.json` (2026-11-25).
- [x] Gate approved by the product owner (2026-11-25).

Release 1.0.0 (2026-11-25):
- [x] Built with `scripts/release.ps1` and signed with the release key. The signature was checked against the public key in `tauri.conf.json`: valid for the installer and for version 1.0.0; a changed installer is rejected.
- [x] Tagged `v1.0.0`, for the GitHub release of the same name with the installer, its signature, `latest.json` and `SHA256SUMS.txt`.
- [ ] The release checklist (RELEASING.md) on the published installer.

Still open (product owner):
- Optional: an Authenticode certificate (D-016).
- Review the OpenPhish/PhishTank terms for the phishing list (D-032).
- Legal review of the licence and notices (D-017).

**Exit:** release checklist (TESTING §8) passes on a clean Windows 11 GA VM → v1.0. *Status: replaced by D-054 (this PC). Everything passes except the two open items above. Release 1.0.0 is built and tagged; the items under "Still open" remain.*

---

## Explicitly not planned (scope guard)

Accounts, sync, cloud services, telemetry, VPN, antivirus, password manager, extension store, bookmarks sync, reading mode, AI features, "security score", system-wide DNS/proxy/firewall changes, TLS interception. Any addition requires a DECISIONS entry and product-owner approval.

## After 1.0.0 · bookmarks and theme fixes · **release 1.1.0** (built and signed 2026-11-25; D-055, D-053)

The product owner asked for bookmarks and reported grey areas in the Black theme.
- **Bookmarks (D-055):**
  - A star in the address bar and Ctrl+D (also inside pages) add the page; a button beside the address bar opens the bookmarks panel.
  - The panel has search, one-level folders, editing with Up and Down, import and export of the standard bookmarks file, and "Delete all".
  - The icon is the one the page showed; nothing is fetched.
  - Unit tests in `untrace-core::bookmarks`; fuzz target `bookmarks_file`.
  - Tried by hand in a scratch data folder: Ctrl+D inside a page, rename, new folder, move into it, import of a Chrome-format file (2 entries skipped: a `javascript:` bookmarklet and a local file), search, export, re-import, the star on a page with its own icon.
- **Theme fixes (D-053):** the Windows title bar takes the theme's colour; an empty tab shows the interface's background instead of the engine's grey blank page. Checked by sampling the screen in the Black theme: title bar `#060607` like the tab strip, empty tab `#000000`.

## After 1.1.0 · sleeping tabs · **release 1.2.0** (built 2026-11-25, released 2026-11-26; D-056)

The product owner asked how UNTRACE's memory compares with Chrome, Brave and Edge.
- **Measured** (their running UNTRACE): about 505 MB: pages 395 MB (the same engine as those browsers), the interface 91 MB, `untrace.exe` 19 MB.
- **Sleeping tabs:** background tabs sleep after 30 minutes by default (Settings › Performance), with the engine's own suspend mechanism; tabs with sound, camera or microphone, or open questions never sleep. Self-check 57.

## After 1.1.0 · ad blocking on hard sites · **release 1.2.0** (built and released 2026-11-26; D-057)

The product owner reported ads, a fake captcha and pop-up tabs on 9anime, and video ads on YouTube.
- **Checked** on the real sites with a new mode of the real-site runner (`compat adcheck`): real clicks, screenshots, requests, YouTube's player ad data.
- **Pop-ups:** the lists' pop-up rules, which the matching library drops (2,977 in EasyList), applied by UNTRACE, also to blank windows sent to an ad (pop-unders). Self-check 58.
- **uBlock Origin's lists** with their `!#if` directives evaluated, and their Safari regex rules (the 9anime ad network is only blocked by those).
- **Scriptlets:** uBlock Origin 1.77.2's scriptlets, bundled; YouTube's ad data removed. Self-check 59.
- **Result:** 9anime.es without captcha, overlay or pop-ups; YouTube without the ad. Open: scriptlets in frames, badware strict blocking, uBlock-only options the engine lacks.

## After 1.2.0 · click redirects on 9anime · **release 1.2.1** (built 2026-11-26; D-058)

The product owner reported that clicks on 9anime still sent them to ads with 1.2.0.
- **Found:** 9anime's own video player (a frame of another site) opened an ad tab on every click. Its ad script was listed by uBlock Origin, but the matching library fuses rules with the same options and one rule it cannot compile (lookahead) disabled the working one. 44 such rules in the uBlock Origin lists.
- **Fixed:** rules the library cannot compile are dropped before the engines are built; uBlock Origin Lite's lookahead-free rules are used too. Built-in canary; self-check 60.
- **Page redirects:** a page can no longer send its tab to a site the lists block as a page (uBlock Origin's strict blocking; this closes the badware gap of D-057 for navigations pages start). The tab stays and shows a notice; addresses the user opens still load. Self-check 61.
- **Result:** no ad tab or redirect in 12 clicks on 9anime's pages and player; the video plays.

## Candidate post-v1 items (need approval)

Optional session restore, default-browser registration (explicit, reversible), ARM64 build, per-site containers beyond temporary sessions.
