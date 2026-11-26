# UNTRACE — Decision Log

Each entry: context, decision, alternatives, consequences, status, and evidence where available.
Status values: **Accepted** · **Proposed** (architect's recommendation, awaiting review) · **Open** (needs the product owner's call) · **Gated** (depends on a spike).
Superseded entries are kept and marked, never deleted. Milestone 0 evidence: `spikes/M0-RESULTS.md` (2026-11-21).

## Index

| ID | Decision | Status |
|---|---|---|
| D-001 | Engine: WebView2 Evergreen | **Accepted** (M0) — real-site overhead still to measure |
| D-002 | Content views via raw WebView2 COM in an UNTRACE container window | **Accepted** (S1) |
| D-003 | Separate WebView2 environments for UI and content | **Accepted** (M1 experiment) — revisit when Tauri exposes custom crash reporting |
| D-004 | Filtering engine: adblock-rust | **Accepted** (S2) |
| D-005 | Layered filtering | **Accepted** (S2, S3, S6) |
| D-006 | Encrypted DNS only via app-scoped loopback proxy | **Accepted** (S3; built in M5) — depends on an unsupported flag |
| D-007 | No TLS interception, ever | Accepted |
| D-008 | No certificate-error bypass in v1 | Proposed |
| D-009 | HTTPS-only enforced by UNTRACE navigation policy | Proposed |
| D-010 | Third-party cookies: honest partial restriction, no "block all" in v1 | **Accepted** (S6) |
| D-011 | Fingerprinting: modest reduction, no anonymity claims | **Accepted** (2026-11-24, M8 evidence) |
| D-012 | SmartScreen default: off | **Accepted** (2026-11-21) |
| D-013 | No telemetry; crash dumps local | Accepted (S5 evidence) |
| D-014 | Retention defaults | **Accepted** (S5) |
| D-015 | Cosmetic injection vehicle: embedded-data main-world script | **Accepted** (S4) |
| D-016 | Update channels; automatic daily check; GitHub Releases; unsigned until a certificate is bought | **Accepted** (2026-11-25) |
| D-017 | UNTRACE licence: MPL-2.0 | **Accepted** (2026-11-25) |
| D-018 | Default search engine: DuckDuckGo; suggestions off | **Accepted** (2026-11-25) |
| D-019 | Supported platforms: Windows 11 x64 | **Accepted** (2026-11-21) |
| D-020 | Dependency policy | Accepted |
| D-021 | UI never overlaps content | Proposed |
| D-022 | Extensions disabled in content environment | **Accepted** (S4) |
| D-023 | Encrypted DNS default mode: Automatic | **Accepted** (2026-11-21) |
| D-024 | Use the Windows native DoH API, not a resolver crate | **Accepted** (S3) |
| D-025 | Runtime background traffic blocked when the network layer is on | **Accepted** (2026-11-21) |
| D-026 | Keep proxy authentication; absorb the first-navigation auth artifact | Accepted (M5, technical) |
| D-027 | Own tracking-parameter list, removed by redirecting the request | **Accepted** (M4, technical) |
| D-028 | Random names for temporary profiles | Accepted (S5) |
| D-029 | Error panels and questions live in the trusted UI, never in page content | Accepted (M2) |
| D-030 | HTTPS-only details: loopback exempt, session-only exceptions, loop guard | Accepted (M2) |
| D-031 | Permission, external-application and download policy | Proposed (M2) |
| D-032 | Block lists, defaults and matching | **Accepted** (2026-11-22) |
| D-033 | Malware/phishing warning: "Continue anyway" for the session only | **Accepted** (2026-11-22) |
| D-034 | Worker requests through one owner tab; blocked requests answered with an empty 403 | Accepted (M3, technical) |
| D-035 | Tracking prevention default: Balanced | **Accepted** (2026-11-22) |
| D-036 | Temporary tabs: one shared InPrivate session in the main window | **Accepted** (2026-11-22) |
| D-037 | No "delete third-party cookies when a tab closes" | **Accepted** (2026-11-22) |
| D-038 | Clearing on exit, with a start-up fallback | Accepted (M4, technical) |
| D-039 | Remove the engine's per-site engagement records and temporary-profile entries at start-up | **Accepted** (2026-11-22) |
| D-040 | Local-network protection, with a DNS-rebinding guard | **Accepted** (2026-11-22) |
| D-041 | Encrypted-DNS providers for "Strict": Quad9, Cloudflare, Mullvad, or your own | **Accepted** (2026-11-22) |
| D-042 | Network backstop: malware and phishing hosts only | **Accepted** (2026-11-22) |
| D-043 | Scriptlets deferred until the licence decision (D-017) | Superseded by D-057 (2026-11-26) |
| D-044 | Extended (procedural) hiding rules not applied in M6 | **Accepted** (2026-11-23) |
| D-045 | "Hide the space blocked ads leave": own switch, on; generic rules by observation | **Accepted** (2026-11-23) |
| D-046 | Self-check from Diagnostics, in a separate test instance | **Accepted** (2026-11-23) |
| D-047 | Security report: one HTML file, without browsing data | **Accepted** (2026-11-23) |
| D-048 | Fingerprint baseline: Google Chrome and bare WebView2 (Edge is not installed on the test machine) | **Accepted** (2026-11-24) |
| D-049 | Fingerprinting measures evaluated in M8: remove WebView2 tells, only where consistent everywhere | **Accepted** (2026-11-24) |
| D-050 | Fuzzing: coverage-guided (nightly Rust + cargo-fuzz), with randomized tests as the fallback | **Accepted** (2026-11-24) |
| D-051 | Dependency review: cargo-deny and cargo-audit installed and run in every full check | **Accepted** (2026-11-24) |
| D-052 | "Keep WebRTC inside the network layer": own switch, on | **Accepted** (2026-11-24) |
| D-053 | Appearance: Black theme, accent colour presets, websites follow the theme | **Accepted** (2026-11-24) |
| D-054 | M9 release checklist run on the development PC, not a clean VM | **Accepted** (2026-11-25) |
| D-055 | Bookmarks: local only, a side panel, one-level folders, HTML import and export | **Accepted** (2026-11-25) |
| D-056 | Sleeping tabs: background tabs suspended after 30 minutes by default | **Accepted** (2026-11-25) |
| D-057 | Ad blocking on hard sites: pop-up rules, uBlock Origin's lists and scriptlets | **Accepted** (2026-11-26) |

---

### D-001 — Engine: Microsoft Edge WebView2 (Evergreen)
- **Context:** UNTRACE must not build an engine. Candidates: WebView2 Evergreen, WebView2 Fixed Version, CEF, Electron, others (FEASIBILITY §3.3).
- **Decision:** WebView2 Evergreen runtime.
- **Alternatives:** Fixed Version (we would own Chromium patching — rejected). CEF/Electron (full control incl. DoH and cookie prefs, but we would own a 1–4-week security-patch cadence). Electron remains fallback #1.
- **Consequences:** Engine security patches arrive from Microsoft automatically. Limitations L1–L10 accepted and shown in Settings next to the affected protections.
- **Evidence:** All six spikes ran on runtime 157.0.4341.60; no gate failed in a way that requires another engine. S6's failure lands on the planned fallback (D-010).
- **Status:** Accepted. Open item: real-site page-load overhead (S2) — needs approval to visit real sites.

### D-002 — Content views via raw WebView2 COM, inside an UNTRACE container window
- **Context:** Tauri injects `__TAURI_INTERNALS__` and plugin scripts into every webview and registers its protocols there; child webviews require the `unstable` feature. CVE-2026-42184 showed remote origins being treated as local on Windows.
- **Decision:** Tauri owns the window and the trusted UI view. Content views are created with `webview2-com` and parented to an **UNTRACE-owned child window** (`WS_CHILD | WS_CLIPSIBLINGS`, kept at `HWND_TOP`) that UNTRACE positions over the content area. No host objects, web messages, injected app globals or custom protocols.
- **Evidence (S1):** Parented directly to the Tauri window, the content view ends up *below* Tauri's `WRY_WEBVIEW` and is invisible. Inside the container it renders correctly, follows resizes, and receives Ctrl+L/Ctrl+T via `AcceleratorKeyPressed`. No Tauri globals were present in content.
- **Consequences:** UNTRACE owns layout, z-order, focus and accelerator routing for content. Manual checks pending: DPI change, IME, mouse focus hand-off.
- **Status:** Accepted.

### D-003 — Separate WebView2 environments for UI and content
- **Context:** Environment-wide options (browser arguments, tracking prevention, extensions, crash reporting) must be controlled by UNTRACE for content. Tauri creates the UI view's environment with its own options.
- **Decision:** Two user-data folders → two environments.
- **Evidence:**
  - S1 measured ~115 MB of overhead for the second environment.
  - The M1 experiment (`spikes/m1-shared-env/RESULTS.md`) ran content views in Tauri's environment, with their own profile:
    - private memory 395 → 275 MB median (**−120 MB, −30 %**); working set 652 → 397 MB (**−39 %**);
    - 11 of 12 self-checks unchanged, including "no Tauri globals in content";
    - **"Crash reports stay on this device" fails**: wry 0.57 never enables WebView2's custom crash reporting, and Tauri 2.12 offers no option for it.
- **Why not shared:**
  - It would break D-013.
  - wry's default arguments also disable SmartScreen outright, which blocks the user's opt-in under D-012, so they would have to be restated.
  - A browser-process failure would take down the UI as well as the pages.
- **Revisit when:** Tauri/wry exposes custom crash reporting (draft upstream request: `spikes/m1-shared-env/upstream-request.md`). Then switch, restate the browser arguments, and re-run `measure.ps1` and the self-check.
- **Consequences:** ~120 MB extra private memory. The experimental switch `UNTRACE_EXPERIMENT_SHARED_ENV` stays for that re-test. While it is on, the self-check fails, so it cannot ship by accident.
- **Status:** Accepted (2026-11-21).
### D-004 — Filtering engine: adblock-rust
- **Decision:** `adblock` crate (Brave), MPL-2.0, pinned minor version (0.13.x).
- **Evidence (S2):** EasyList + EasyPrivacy (136,500 lines) build in 96 ms; serialized engine 6.1 MB, deserialized in 1.7 ms; matching p50 7 µs / p99 42 µs inside the WebView2 event handler.
- **Alternatives:** uBlock Origin Lite as extension (no UI in WebView2, not controllable from Settings, GPL-3.0); own engine (unjustified).
- **Consequences:** Must supply scriptlet/redirect resources ourselves (pinned uBO resource set, GPL-3.0 — see D-017). Ship a serialized engine cache keyed by crate version.
- **Status:** Accepted.

### D-005 — Layered filtering
- **Decision:** (1) adblock-rust at navigation and request level, using `AddWebResourceRequestedFilterWithRequestSourceKinds(ALL)`; (2) Edge tracking prevention; (3) loopback-proxy domain backstop.
- **Evidence:** S2 — the source-kinds API sees every tested request type **except WebSockets** (the legacy filter also misses cross-origin iframe sub-resources and all worker traffic). S3 — WebSockets do pass through the proxy as `CONNECT`. S6 — tracking prevention Strict blocks known trackers while neutral third parties load.
- **Consequences:** WebSocket blocking exists only in the network layer, and only by host name. Interception costs ~0.17 ms per request (cross-process hop), measured on loopback.
- **Status:** Accepted.

### D-006 — Encrypted DNS only via an app-scoped loopback proxy
- **Decision:** Optional loopback HTTP proxy (CONNECT + plain-HTTP forwarding) with per-launch credentials; it resolves names via DoH (D-024). WebView2 is pointed at it with `--proxy-server` and `--proxy-bypass-list=<-loopback>`.
- **Evidence (S3):** All page traffic types went through the proxy; Chromium net-log shows no DNS jobs for proxied names; with the proxy stopped, loads fail and nothing goes direct.
- **Consequences:** Relies on a browser flag Microsoft says not to use in production (L3). At runtime UNTRACE must keep checking that navigations actually pass through the proxy. Without the proxy, WebView2 also performs WPAD lookups; the proxy setting stops that.
- **M5 implementation** (`crates/untrace-net`, ARCHITECTURE §2.0e):
  - **Routing:** the engine's only arguments are `--proxy-server=http://127.0.0.1:<port> --proxy-bypass-list=<-loopback>`.
  - **Start-up check:** a request from the engine to a random check name must reach the proxy with this launch's credentials before the first page loads.
  - **Fail closed:** if the proxy cannot start, no page opens.
  - **Local-network finding (S7):** through the proxy, Chromium classes every page as "Loopback" (the proxy's address). This weakens nothing today, because WebView2 enforces no local-network protection at all, but it is why D-040 exists.
- **Status:** Accepted.

### D-007 — No TLS interception, ever
- **Decision:** UNTRACE never installs a root certificate and never decrypts traffic. The proxy is a blind tunnel.
- **Status:** Accepted.

### D-008 — No certificate-error bypass in v1
- **Decision:** `ServerCertificateErrorDetected` → always cancel; UNTRACE error page shows details; no "proceed anyway".
- **Consequences:** Some intranet/self-signed devices are unreachable in UNTRACE. (Test builds accept only a fingerprint-pinned fixture CA, compiled out of releases — TESTING §2.)
- **Status:** Proposed.

### D-009 — HTTPS-only enforced by navigation policy
- **Decision:** Upgrade `http://` navigations (top-level and frames). If HTTPS fails, show an UNTRACE page; continuing over HTTP is a per-site, per-session user action.
- **M5 finding and fix:** cancelling the `http://` navigation at `NavigationStarting` did not stop its request. The engine still sent the plain-HTTP request, query included (`spikes/m5-network/RESULTS.md`). UNTRACE now answers the request of every navigation it cancels with 403 in `WebResourceRequested`, so nothing unencrypted leaves (self-check 43).
- **Status:** Proposed.

### D-010 — Third-party cookies: honest partial restriction
- **Context:** No supported WebView2 API (L1).
- **Evidence (S6):** Baseline: third-party cookies are sent cross-site. DevTools `Network.setCookieControls` cleans request headers **only in the view where it was called**. Another view in the same profile is unprotected, and JavaScript in cross-origin iframes can still read cookies.
- **Decision:** No "Block all third-party cookies" setting in v1. The protection is labelled "Restrict known trackers' cookies". It is implemented by tracking prevention (level verified by read-back), tracker lists, and an optional "clear third-party cookies when the tab closes".
- **Status:** Accepted.

### D-011 — Fingerprinting: modest reduction, no anonymity claims — **Accepted**
- **Evidence (S1):** Pages can see that they run in WebView2. The client-hint brands include "Microsoft Edge WebView2", and `chrome.webview` with `postMessage`/`hostObjects` stays present even when the bridge is disabled.
- **Decision:** v1 = tracker/fingerprinter lists and tracking prevention; no UA override (it clears client hints and makes users more unique). Settings state plainly that UNTRACE users are distinguishable as WebView2 users. Any script-level mitigation is evaluated at M8 with a fingerprint harness.
- **M8 evidence** (`spikes/m8-fingerprint/RESULTS.md`, D-048, D-049):
  - **WebView2's tells, compared with Chrome on the same machine:**
    - the "Microsoft Edge WebView2" brand, in the `Sec-CH-UA` header of every request and in `navigator.userAgentData` everywhere;
    - `chrome.webview`;
    - no Payment Request API;
    - only the 4 local speech voices;
    - `DNT: 1`, which the engine switches on by itself about 2.5 s after it starts.
  - **What UNTRACE adds:** UNTRACE's own settings add nothing a page can read. Two UNTRACE sessions and a bare WebView2 gave identical values, and UNTRACE introduced no inconsistency between page, frames and workers.
  - **No measure passes D-049:**
    - Removing the brand by the DevTools protocol, by script or with `Settings.UserAgent` leaves it in cross-site frames, workers or headers, which a page can detect.
    - Hiding `chrome.webview` is consistent but removes no information, because the brand already names WebView2 on every request.
- **Status:** Accepted by the product owner at the M8 gate, 2026-11-24. No fingerprinting measure is adopted; UNTRACE users are recognisable as WebView2 users. Settings says so under "Block trackers" (added at the gate: the decision had asked for it since S1, but the text was missing).

### D-012 — SmartScreen default — **Accepted: off**
- **Context:** SmartScreen provides phishing/malware reputation and download checks, but sends information about visited sites to Microsoft and requires a user notice.
- **New evidence (S3):** `IsReputationCheckingRequired=false` stops the SmartScreen traffic. With the network layer on, the runtime's SmartScreen requests **cannot pass the authenticated proxy** (they are not tied to a view, so no credentials are supplied). So enabling SmartScreen together with encrypted DNS also requires D-025.
- **Options:** (A) Off by default, explained, user can enable. (B) On by default with first-run notice. (C) First-run choice with no pre-selection.
- **Recommendation:** **A.** Windows-level protections still apply: downloads get Mark-of-the-Web (verified, S5), so Defender and OS SmartScreen check them when opened.
- **Decision:** **A — off by default**, explained in Settings and at first run; the user can enable it.
- **Status:** Accepted by the product owner, 2026-11-21.

### D-013 — No telemetry; crash dumps local
- **Decision:** UNTRACE sends no analytics, usage or error reports. `IsCustomCrashReportingEnabled = true`; dumps land in `<user-data>\EBWebView\Crashpad\reports` (verified, S5) and are deleted after 7 days. Microsoft's required runtime diagnostic data cannot be disabled by apps; this is disclosed.
- **Status:** Accepted.

### D-014 — Retention defaults
- **Evidence (S5):** WebView2 writes browsing history to disk; `ClearBrowsingData(BROWSING_HISTORY)` removes it. Cookies are encrypted at rest. InPrivate profiles leave no page data on disk after closing.
- **Decision:** History and cache cleared on exit; cookies kept (sign-ins work) with a one-switch "clear cookies on exit"; no session restore; per-tab transparency data in memory only; audit log capped at 1 MB with no URLs.
- **Status:** Accepted.

### D-015 — Cosmetic injection vehicle
- **Evidence (S4):**
  - Fetching rules from a local endpoint is blocked by strict CSP (`connect-src`).
  - Per-navigation registration loses a race on the first load.
  - The DevTools isolated world did not apply.
  - Extension `insertCSS` causes a visible flash.
  - A **main-world document-start script with the rules embedded, applied via `adoptedStyleSheets`**, hid elements on strict-CSP pages and in cross-origin frames, before first paint, with no CSP reports.
- **Decision:** Vehicle a3. One registered script per filter-list version carries generic CSS plus a hostname-indexed table of site-specific rules, picks rules by `location.hostname`, and is re-registered on list updates.
- **Consequences:** ~190 KB generic + ~480 KB site-specific data for EasyList/EasyPrivacy. Per-frame parse and memory cost becomes an M6 budget, with a fallback to a reduced generic set. Main-world code is visible to pages and must never hold secrets.
- **Status:** Accepted.

### D-016 — Update channels and check policy
- **Decision (Proposed):** Engine via Microsoft Evergreen. App via Tauri updater (Ed25519-signed manifest, Authenticode-signed installer). Lists from upstream maintainers over HTTPS with validation and rollback. Tauri pinned at ≥ 2.12.7 (current stable; Tauri 3 is alpha — not considered before it is stable).
- **Decided:** automatic app update checks **on, daily, disclosed**, and the user can turn them off (product owner, 2026-11-21).
- **Hosting (product owner, 2026-11-25):** GitHub Releases, from a repository whose releases are public ([MiniJohan/UNTRACE-Browser](https://github.com/MiniJohan/UNTRACE-Browser)). The updater reads a signed manifest (`latest.json`) from the latest release. GitHub's private vulnerability reporting is the security channel (SECURITY.md).
- **Code signing (product owner, 2026-11-25):** unsigned for now. The release process has Authenticode signing as an optional step; a certificate or signing service is bought before a public release. Until then Windows SmartScreen warns on the downloaded installer.
- **Update signing:** Ed25519 (Tauri updater). The private key and its password are created and kept by the product owner, never in the repository; tests use a separate throw-away test key.
- **Status:** Accepted, 2026-11-25.

### D-017 — UNTRACE licence — **Open**
- **Context:** adblock-rust is MPL-2.0; uBO resources and several filter lists are GPL-3.0 (bundled as separate data files).
- **Options:** MPL-2.0, GPL-3.0, or proprietary (bundling GPL lists then needs care).
- **Decision (product owner, 2026-11-25):** **MPL-2.0** for UNTRACE's own code (`LICENSE`, the `license` field of every crate and of the UI package). The same licence as adblock-rust, Firefox and Brave. Bundled lists and dependencies keep their own licences (`crates/untrace-filter/lists/NOTICE.md`, third-party notices shipped with the installer).
- **Consequence for D-043:** GPL-3.0 scriptlet resources would be a separate, separately licensed data file. That needs its own review before it ships.
- **Status:** Accepted, 2026-11-25. A legal review before the first public release is still advisable.

### D-018 — Default search engine and suggestions — **Open**
- **Decision (Proposed):** a privacy-respecting default chosen by the product owner; user-selectable; **search suggestions off**.
- **Provisional (development only):** DuckDuckGo is the default in M1 builds so the address field works; Startpage, Brave Search, Mojeek and a custom template are selectable. To be confirmed before any release.
- **Decision (product owner, 2026-11-25):** DuckDuckGo is the default; the others stay selectable; search suggestions stay off.
- **Status:** Accepted, 2026-11-25.

### D-019 — Supported platforms — **Accepted: Windows 11 x64**
- **Decision:** **Windows 11 x64** is the supported target. Windows 10 is not supported: it lacks the native DoH API (D-024). ARM64 later.
- **Status:** Accepted by the product owner, 2026-11-21.

### D-020 — Dependency policy
- **Decision:** Every new dependency needs a reason in this log; prefer platform APIs; `cargo deny` + `cargo audit` + lockfiles in CI; UI limited to React + Tauri API.
- **Status:** Accepted.

### D-021 — UI never overlaps content
- **Context:** Airspace limitation (L9), confirmed by S1's z-order finding.
- **Decision:** Side panels resize the content container; full-page Settings/Diagnostics hide it; rare overlays use an owned popup window.
- **Status:** Proposed.

### D-022 — Extensions disabled in the content environment
- **Decision:** `AreBrowserExtensionsEnabled = false`. The S4 extension vehicle worked for static CSS but flashed for dynamic rules, and is not needed now that vehicle a3 is chosen.
- **Status:** Accepted.

### D-023 — Encrypted DNS default mode — **Accepted: Automatic**
- **Evidence (S3):** Without the proxy, WebView2 resolves names with Chromium's built-in DNS client in "Automatic" secure-DNS mode. On this machine that meant **unencrypted** queries to the system-configured servers, plus WPAD lookups. Windows' own DNS cache is bypassed.
- **Options:**
  - (A) *System*: no proxy. Chromium behaves as above.
  - (B) *Automatic*: proxy on. DoH via the Windows native API when the user's configured DNS server has a known DoH endpoint, otherwise system resolution. No new third party.
  - (C) *Strict DoH*: proxy on, with a chosen provider and no fallback.
- **Decision:** **B — Automatic.**
- **M5:** "known DoH endpoint" means Windows' own list (`DohWellKnownServers`: Quad9, Cloudflare, Google) or the adapter's DoH template set in Windows. If a DoH lookup fails, Windows' resolver answers; each such fallback is counted in Diagnostics. On the development machine, the DNS server is a local one (`192.168.1.26`) with no known endpoint, so Automatic uses the Windows resolver there. Diagnostics says so in words.
- **Status:** Accepted by the product owner, 2026-11-21.

### D-024 — Windows native DoH API instead of a resolver crate
- **Evidence (S3):** `DnsQueryEx` with `DNS_QUERY_REQUEST3` + `DNS_CUSTOM_SERVER` (DoH template) resolves names; a wrong DoH path fails with 9002, which proves the query used DoH with no UDP fallback. Constraints: server port must be 0; `DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE` is rejected.
- **Decision:** Use the OS API; drop `hickory-resolver` from the plan. Windows 10 lacks this API, which is one more reason for D-019 = Windows 11.
- **Status:** Accepted.

### D-025 — Runtime background traffic when the network layer is on — **Accepted: blocked**
- **Evidence (S3):** The runtime contacts `config.edge.skype.com` (configuration/experimentation) on its own, and `nav-edge.smartscreen.microsoft.com` when SmartScreen is on. These requests are not tied to a view, so they cannot answer the proxy's auth challenge and are effectively blocked.
- **Options:** (A) Block all runtime background traffic (privacy-maximal; SmartScreen and runtime configuration stop working while the network layer is on). (B) Allow a short, documented list of Microsoft endpoints without auth (they still bypass UNTRACE's DoH unless resolved by the proxy). (C) Allow everything from the runtime.
- **Decision:** **A** — blocked by default, every blocked host listed in Diagnostics. B is offered only when the user enables SmartScreen.
- **M5:** implemented. Requests without this launch's credentials get `407` and nothing else. Diagnostics lists the hosts that were only ever asked for without credentials as the runtime's background traffic. SmartScreen stays off (D-012), so option B is not built yet.
- **Status:** Accepted by the product owner, 2026-11-21.

### D-026 — Keep proxy authentication; absorb the first-navigation auth artifact
- **Evidence (S3):** With proxy auth, the first navigation fires `NavigationCompleted` with status 18 (proxy auth required) before the authenticated retry succeeds.
- **Decision:** Keep per-launch credentials (they stop other local processes from using the proxy). The content view manager treats status 18 as transient and never shows it to the user. Alternatively, warm up credentials with a hidden navigation at startup.
- **M5:** both are built.
  - The start-up check sends a request from the first tab to a random `*.untrace.invalid` check name. The engine answers the proxy's challenge there, before any page loads.
  - Credentials are given only when the challenge carries this launch's random realm, so a site's own sign-in request is never answered with them.
  - A status-18 completion is ignored.
- **Limitation found in M5 (self-check 40):** the engine answers the proxy's challenge for ordinary requests, not for WebSockets, and keeps the credentials per site.
  - Normally harmless: a page loaded from the network has already made requests through the proxy before it opens a WebSocket, so its WebSockets carry the credentials.
  - A page served entirely from the cache or a service worker that opens a WebSocket before any other request will see that WebSocket fail.
  - Accepted; revisit if real sites break.
- **Status:** Accepted (technical, M5).

### D-027 — Own tracking-parameter list, removed by redirecting the request
- **Evidence (S2):** EasyList/EasyPrivacy contain no `$removeparam` rules for common link-decoration parameters (`utm_*`, `gclid`, `fbclid`, `msclkid`, …).
- **Evidence (M4):** adblock-rust 0.13 matches `$removeparam` by exact name only (no `utm_*`), so the list is matched by UNTRACE itself (`untrace_filter::params`, ~50 names, the `utm_` prefix, and four share parameters that are removed only on their own site, e.g. YouTube's `si`).
- **Decision:**
  - A page or frame **GET** request whose address carries listed parameters is answered, in `WebResourceRequested`, with a `307` redirect to the cleaned address. Other parameters keep their order and exact encoding (text-level edit; re-encoding could break signed addresses). Form POSTs are never touched.
  - Verified with a local fixture (`spikes/m4-privacy/RESULTS.md`): the server never receives the parameters, including after a server redirect *to* a tracked address (the event fires for each redirect hop) and in frames; the page's own `location` is clean; a POST to a tracked address is left alone.
  - The site panel lists the removed names; Settings has one switch (on by default). There is no per-site exception: the parameters never change what a page shows.
- **Status:** Accepted (technical, M4).

### D-028 — Random names for temporary profiles
- **Evidence (S5):** After an InPrivate profile closes, an empty `WV2Profile_<name>` folder remains.
- **Decision:** Temporary profile names are random and carry no information; leftover empty folders are removed on startup.
- **M4:** the engine reopened the last used temporary profile at the next start (it is recorded in `Local State`), recreating its folder; UNTRACE now removes those entries first (D-039).
- **Status:** Accepted.

### D-029 — Error panels and questions live in the trusted UI, never in page content
- **Context:** A browser must explain refusals (certificate, HTTPS, load errors) and ask questions (permissions, other applications, downloads). Drawing these inside the page view would need a bridge from web content to UNTRACE, which D-002 forbids. Drawing over the page is impossible (L9).
- **Decision:**
  - Error panels are drawn by the UI in the page area while the host hides that tab's page view and its container.
  - Questions appear in a prompt bar above the page that pushes it down.
  - The engine's built-in error pages are off (`IsBuiltInErrorPageEnabled = false`), so the engine never offers its own "continue anyway".
  - When a panel replaces the active page, keyboard focus moves to the panel's main button.
- **Consequences:** Every button that weakens protection runs in the trusted UI and goes through validated commands.
- **Status:** Accepted (2026-11-21).

### D-030 — HTTPS-only details
- **Decision:**
  - On by default (Settings toggle).
  - Top-level `http://` navigations are cancelled and re-issued as `https://` (port 80 dropped).
  - A redirect loop back to HTTP stops after two hops and shows the panel.
  - Loopback hosts (`localhost`, `*.localhost`, 127.0.0.0/8, ::1) are exempt; private network addresses are not.
  - "Continue over HTTP" allows that host until UNTRACE closes; nothing is persisted.
  - Frames and sub-resources follow the engine's mixed-content rules.
- **Known limit:** a form POST to an `http://` address is re-issued as a GET to `https://`, so the form data is not re-sent.
- **Status:** Accepted (2026-11-21).

### D-031 — Permission, external-application and download policy
- **Permissions:**
  - **Asked about:** camera, microphone, location, notifications, clipboard read, file access, multiple downloads.
  - **Refused without asking:** motion sensors, installed fonts (fingerprinting), MIDI system-exclusive messages, window management, autoplay, unknown kinds.
  - Decisions are saved only with "Remember for this site", which uses the engine's per-profile storage and can be listed and reset.
  - At most 3 open questions per tab; extra requests are refused.
  - Questions from a page being left are answered "no".
- **Other applications:**
  - Abused link types are refused outright: `ms-msdt`, `search-ms`, `ms-appinstaller`, `ms-officecmd`, `ms-settings`, help-file schemes, `file`/`shell`/script schemes.
  - Every other application link is asked about each time and only after a user gesture. Nothing is remembered.
- **Downloads:**
  - Every download is a question first, then the Windows save dialog.
  - Programs, scripts, installers, disk images and macro documents are flagged.
  - Files keep the engine's Mark-of-the-Web (M0/S5). Windows decides the zone: files from Internet-zone addresses get `ZoneId=3` plus `ReferrerUrl`/`HostUrl`; files from `localhost` or the local network (intranet zone) get no mark. Verified 2026-11-22 through the real save dialog (127.0.0.1 → marked, localhost → not marked) and in self-check 23.
  - Privacy note: the mark stores the page and file address inside the saved file (an NTFS stream). UNTRACE keeps it, because Windows and Office rely on it to warn before opening downloaded files; removing it would weaken security.
  - The download list is kept only in memory for the session.
- **Status:** Proposed — implemented as described; open to product-owner adjustment (for example, whether location should be refused by default).
### D-032 — Block lists, defaults and matching
- **Lists** (all four on by default, each with its own switch; product owner, 2026-11-22):

  | List | Blocks | Source | Licence | Format | Update |
  |---|---|---|---|---|---|
  | EasyList | Ad requests | easylist.to | GPLv3 or CC BY-SA 3.0 (used under CC BY-SA 3.0) | Adblock syntax | `Expires`: 4 days |
  | EasyPrivacy | Tracker requests | easylist.to | same | Adblock syntax | 4 days |
  | URLhaus malware domains | Sites serving malware | malware-filter (from abuse.ch URLhaus) | CC0 / MIT | One host or IP per line | 12 hours |
  | Phishing domains | Phishing sites | malware-filter (from OpenPhish, PhishTank, IPThreat) | CC BY-SA 4.0; OpenPhish/PhishTank are "free of charge" under their own terms, **to be checked before the first release** | One host or IP per line | 12 hours |
- **Matching:**
  - EasyList and EasyPrivacy go into one adblock-rust engine, network rules only. Cosmetic rules arrive with M6.
  - Malware and phishing lists are host sets, so UNTRACE knows which list matched. A listed host also covers its subdomains, never its parent domain (many entries are subdomains of shared hosts such as `*.weebly.com`).
  - The full URLhaus URL list (12 MB) is not used. The domain list (32 KB) covers whole malicious hosts.
- **No GPL resources in M3:** `$redirect` rules block the request without substituting a neutered script; adblock-rust does this when a resource is missing. Breakage is measured on the corpus. Redirect resources and scriptlets come with M6 and D-017.
- **Shipping:** snapshots are bundled for an offline first run and updated from upstream over HTTPS when each list's `Expires` says so (D-016). Updates are validated (size cap, format, rule count against the previous version) and the last good copy is kept.
- **Licence impact:** none of these needs D-017. Attribution ships with the lists.
- **Status:** Accepted 2026-11-22.

### D-033 — Malware/phishing warning: "Continue anyway" for the session only
- **Context:** Unlike certificate errors, the connection is intact; community lists sometimes contain innocent sites.
- **Decision:**
  - Opening a page on a listed host shows UNTRACE's warning panel in the trusted UI (D-029), naming the list. "Go back" is the default.
  - "Continue anyway" exempts that host until UNTRACE closes. It is never saved, and it is counted in the site panel.
  - Parts of other pages that come from a listed host are blocked and counted.
  - Turning ads/trackers off for a site does not turn off malware or phishing protection.
- **M5 finding and fix:** the warning cancels the navigation at `NavigationStarting`, but the engine still sent the page request to the listed site (`spikes/m5-network/RESULTS.md`). UNTRACE now answers that request itself with 403, so the site receives nothing. With encrypted DNS on, the network layer also refuses the engine's own connection attempts to the host (D-042). With it off, a bare connection attempt (no request) is still possible.
- **Status:** Accepted by the product owner, 2026-11-22.

### D-034 — Worker requests through one owner tab; blocked requests answered with an empty 403
- **Context:** WebView2 raises shared/service-worker requests on *every* view registered for them (S2). §5.2 planned a hidden sentinel view to receive them once.
- **Decision:**
  - Exactly one live tab (the "worker owner") registers the worker source kinds; when it closes, the next live tab takes over (`claim_worker_requests`). No extra hidden view, so no extra renderer memory. Self-check 16 verifies that a shared worker's request is blocked and counted once.
  - Blocked requests get a response UNTRACE creates: status 403, empty body, `Cache-Control: no-store`. WebView2 cannot produce a network error from this event. Scripts, images and frames fail to load as with other blockers; `fetch()` sees a 403 (or a CORS failure across origins).
- **Consequences:** Worker requests have no tab, so they are counted per session (Diagnostics), not per page, and matched with their `Referer` as the page. WebSockets are never raised (S2) and stay unfiltered until the network layer (M5).
- **M4:** each profile has its own workers, so the temporary profile has its own owner tab. Measured: a temporary tab's shared-worker request is blocked and counted exactly once.
- **Status:** Accepted (technical, M3).

### D-035 — Tracking prevention default: Balanced
- **Evidence (S6):** the level is read back from the engine. Strict stopped 6/6 known tracker hosts from loading; Balanced restricts their storage (third-party cookies of known trackers) rather than their loading.
- **Decision:** Settings › Privacy › Tracking prevention offers Off, Basic, Balanced and Strict; the default is **Balanced**. The level belongs to the engine profile, so UNTRACE sets it on the standard profile and on every temporary profile, and reads both back (they must agree).
- **Why not Strict by default:** EasyPrivacy already blocks most of the same trackers, and Strict breaks more embedded videos, social widgets and sign-ins.
- **Status:** Accepted by the product owner, 2026-11-22.

### D-036 — Temporary tabs: one shared InPrivate session in the main window
- **Decision:**
  - A temporary tab (Ctrl+Shift+N, or the dashed button next to "New tab") uses an InPrivate profile with a random name (D-028). All open temporary tabs share it, like a private window; pop-ups from a temporary tab are temporary too. When the last temporary tab closes, the session ends and the next temporary tab gets a new profile.
  - Temporary tabs are marked by a dashed outline, their own icon and a "Temporary" label in the address field (never by colour alone).
  - Choices that would otherwise be saved stay in the session: a per-site blocking exception made in a temporary tab is kept in memory only; "Remember for this site" is stored in the InPrivate profile and discarded with it.
  - Filtering, HTTPS-only, warnings and tracking prevention apply exactly as in normal tabs.
- **Evidence (M4):** cookies, local storage and IndexedDB written in a temporary tab are invisible to normal tabs and absent from every file on disk after the tab closes, while the same data written from a normal tab is found (self-check 23, probe). The engine leaves an almost empty `WV2Profile_temp-…` folder, removed at the next start.
- **Limitations:** downloaded files stay where they were saved; crash reports could contain page memory; the engine shares its process-level caches (e.g. DNS, compiled shaders) between profiles.
- **Status:** Accepted by the product owner, 2026-11-22 (temporary tabs in the main window, shared session).

### D-037 — No "delete third-party cookies when a tab closes"
- **Context:** D-010 left this optional. The only workable rule ("delete cookies of sites that appeared only embedded in that tab") is fuzzy and signs users out of services embedded on other sites.
- **Decision:** not built. Third-party cookies are restricted through tracking prevention (known trackers), EasyPrivacy, and the optional "Delete cookies and site data when UNTRACE closes".
- **Status:** Accepted by the product owner, 2026-11-22.

### D-038 — Clearing on exit, with a start-up fallback
- **Decision:**
  - Two switches: "Delete the cache when UNTRACE closes" (on, D-014) and "Delete cookies and site data when UNTRACE closes" (off, D-014).
  - On close, the window hides, the engine clears, and the window is destroyed when it reports completion. Site data is then read back: no cookie may be left. Closing waits at most 10 s.
  - The outcome is recorded in `config/exit-clear.json` and the audit log (category only, never a site). While a session runs with either switch on, the record says "pending". If the next start finds anything but "done" (crash, power loss, Windows shutdown, timeout), it clears the owed data before the first page loads; pages wait for it, at most 10 s (then they load and Diagnostics reports the start-up clearing as not verified).
  - Browsing history is cleared at every start regardless (D-014).
- **Status:** Accepted (technical, M4).

### D-039 — Remove the engine's per-site engagement records and temporary-profile entries at start-up — **Accepted**
- **Evidence (M4 probe, `spikes/m4-privacy/RESULTS.md`):** after `ClearBrowsingData` with every relevant kind — site data, cache, history, site settings, and even "all profile data" — and after the engine has flushed and closed, the engine's `Preferences` file still holds `profile.content_settings.exceptions.site_engagement` entries: one per visited origin (scheme, host and port) with a score and time. That is a list of sites visited. Media-engagement entries are removed. Chromium lets engagement scores decay over weeks.
- **Options:**
  - **A. Document only** (current state): Diagnostics and the data page say so.
  - **B. Remove those entries at start-up**, while the engine is not running: parse `Preferences`, delete the two engagement dictionaries, write the file back atomically, and verify by re-reading. Skipped (and reported) if the file cannot be parsed. This edits a file UNTRACE does not own; a future runtime could change its format, in which case B finds nothing and reports that.
- **Recommendation:** B, with A's disclosure kept.
- **Decision:** **B**, by the product owner on 2026-11-22. While implementing it, a second engine record turned up. The engine's `Local State` remembers every temporary profile by name and records the last one used as `last_used`. It reopens that profile at the next start, which recreated the folder UNTRACE had just removed (D-028). So the same start-up step also removes the temporary profiles' entries from `Local State`, and only those.
- **Implementation** (`untrace-webview/src/engine_files.rs`, run in `setup` before the engine starts and only in the first instance):
  - `Local State` first: remove the temporary-profile entries.
  - Then, in each non-temporary profile's `Preferences`, empty the `site_engagement` and `media_engagement` lists.
  - Then remove the leftover temporary folders.
  - Every edit is a JSON parse, a removal of exactly those entries, an atomic write and a read-back check. A file that cannot be parsed is left untouched and reported.
  - The result is in Diagnostics ("Engine records of visited sites removed at start") and the audit log, as counts only.
- **Evidence:**
  - Unit tests: only those entries change; saved permissions and 64-bit and floating-point values survive exactly; a damaged file is not rewritten.
  - The M4 probe on a real engine folder: after the clean-up no file names the visited site; the engine restarts on the edited files and loads pages; the temporary folder does not come back.
- **Status:** Accepted by the product owner, 2026-11-22.

### D-040 — Local-network protection, with a DNS-rebinding guard — **Accepted**
- **Evidence (M5 pre-check S7, `spikes/m5-network/RESULTS.md`):**
  - WebView2 157 applies no local-network protection. The engine's own DevTools report gives `localNetworkAccessRequestPolicy: "Allow"` for a public page's requests to this computer, with or without a proxy, and raises no permission request. Chrome and Edge ask first since version 142.
  - Through a loopback proxy, Chromium gives every page the proxy's address space ("Loopback"), as the WICG specification describes. If WebView2 ever enforced the protection, pages loaded through UNTRACE's proxy would escape it.
  - Declaring the proxy's address public (`--ip-address-space-overrides`) while local destinations bypass the proxy restores the right classes: page "Public", target "Loopback". This is recorded for that day, not used now.
- **Options:** (A) add a protection in M5; (B) record it as a limitation and decide in M8.
- **Decision:** **A**, by the product owner on 2026-11-22.
- **Implementation:**
  - **Request layer** (every tab, and workers through their owner tab): a request whose host is an IP literal in a loopback, private, link-local, carrier-grade-NAT or unique-local range, or a name that is local by its text (`localhost`, `*.localhost`, `*.local`, `*.lan`, `*.home`, `*.home.arpa`, `*.internal`, `*.localdomain`, a name without a dot), coming from a page whose own host is public, gets an empty 403. It is counted in the site panel, where the site can be allowed (saved in Settings; in temporary tabs, until the temporary session ends). Pages that are themselves local may reach the local network.
  - Top-level navigations are not blocked, as in other browsers. Typing a local address or following a link to one works.
  - **Network layer (DNS rebinding):** a public name that resolves to a loopback or local address is refused, unless UNTRACE announced it: the user opened it, or a page that is local or allowed asked for it. A name that resolved to a public address earlier in the session is refused if it later resolves locally (classic rebinding), even when announced.
- **Limitations:** with encrypted DNS off, the rebinding part does not exist. Worker requests are judged by the page they name as referrer. A scripted top-level navigation to a local address is allowed (as in Chrome).
- **Revisit:** if WebView2 starts enforcing Local Network Access, add the S7 "C2" arguments so proxied pages keep the right address space.
- **Status:** Accepted by the product owner, 2026-11-22.

### D-041 — Encrypted-DNS providers for "Strict": Quad9, Cloudflare, Mullvad, or your own — **Accepted**
- **Decision:** Strict offers Quad9 (preselected), Cloudflare and Mullvad, each with its published IPv4 and IPv6 addresses and DNS-over-HTTPS template, plus a custom server (an `https://` template with a path, and an IP address; the template's host name is never looked up).
- **Evidence (M5, `untrace-net/examples/doh.rs`):** all three answer `example.com` over DNS over HTTPS through `DnsQueryEx` on IPv4 and IPv6 addresses (34–69 ms). A wrong DoH path fails with error 9002, so no lookup silently falls back to plain DNS.
- **Rules:**
  - Strict never falls back. A custom provider without a saved server resolves nothing; it does not fall back to Windows either.
  - Names that only exist on the local network (the D-040 local suffixes, names without a dot) go to the Windows resolver in every mode, since a public provider cannot answer them.
- **Status:** Accepted by the product owner, 2026-11-22.

### D-042 — Network backstop: malware and phishing hosts only — **Accepted**
- **Context:** the request layer never sees WebSockets, and the runtime's own traffic belongs to no page (S2, S3).
- **Decision:** the network layer refuses connections to hosts on the enabled malware and phishing lists, the same lists and switches as the page-level warnings. A host the user chose "Continue anyway" for stays allowed for the session (D-033). There is no permanent allow-list, consistent with D-033; this drops the roadmap's earlier "global allow-list". Ad and tracker hosts are not blocked at the network layer: it cannot tell which page a connection belongs to, so per-site exceptions could not apply.
- **Status:** Accepted by the product owner, 2026-11-22.

### D-043 — Scriptlets deferred until the licence decision — **Accepted**
- **Context:** scriptlet rules (`##+js(…)`: 34 in EasyPrivacy, none in EasyList) run small scripts in pages. Those scripts come from uBlock Origin's resource set (GPL-3.0); UNTRACE's licence is open (D-017).
- **Decision:** M6 ships CSS hiding only. Scriptlet rules are counted and shown in Diagnostics as not applied; nothing GPL is bundled. Revisit once D-017 is decided, behind their own setting (ROADMAP M6).
- **Status:** Accepted by the product owner, 2026-11-23. **Superseded by D-057** (2026-11-26): scriptlets run, with uBlock Origin's lists and their switch.

### D-044 — Extended (procedural) hiding rules not applied in M6 — **Accepted**
- **Context:** 294 EasyList rules need code rather than CSS (`:-abp-contains`, `:has-text`, `:upward` …), and 44 carry actions (`:remove()`, `:style()`). `:-abp-has(…)` is standard `:has(…)` and is applied.
- **Decision:** not applied; counted and disclosed in Settings and Diagnostics. Revisit if real sites show visible gaps.
- **Status:** Accepted by the product owner, 2026-11-23.

### D-045 — "Hide the space blocked ads leave": its own switch, on — **Accepted**
- **Decision:** a separate Settings switch (Blocking group, on by default), so layout problems can be fixed without unblocking ads.
  - The per-site "Block ads and trackers" switch turns hiding off for that site too.
  - Only the enabled lists' rules are used.
  - Generic rules are applied by observing the page's classes and ids, not all at once: the M6 spike measured about 3 times less cost (`spikes/m6-cosmetic/RESULTS.md`).
- **Status:** Accepted by the product owner, 2026-11-23.

### D-046 — Self-check from Diagnostics, in a separate test instance — **Accepted**
- **Decision:** Diagnostics › "Run self-check" starts a second UNTRACE with `--self-check`:
  - It runs in its own window ("UNTRACE self-check") and its own data folder (`<data root>\self-check`), offline, with no single-instance lock. The user's tabs, settings and data are not touched.
  - The report is kept (`<data root>\self-check\report.json`). Diagnostics shows it per protection, Settings shows a "Self-test" line under each protection, and the activity log records the result.
  - A run that has not finished in 6 minutes is stopped.
  - The certificate check needs the HTTPS test server that only `scripts/check.ps1` starts, so in the app it is reported as *not run*.
- **Coverage:** `selfcheck::COVERAGE` maps each protection to the checks that exercise it end to end. A unit test fails if a protection has none (the M7 exit criterion).
- **Status:** Accepted by the product owner, 2026-11-23.

### D-047 — Security report: one HTML file, without browsing data — **Accepted**
- **Decision:** Diagnostics › "Save security report…" writes one self-contained HTML page through the Windows save dialog: no scripts, nothing loaded from outside, a strict CSP.
- **Contents:**
  - each protection's setting, read-back state and self-test result;
  - Diagnostics' checks, the last self-check, block lists, the DNS setup;
  - an activity-log summary (the log never holds sites).
- **Never contains:** host names contacted, cookies, downloads, saved per-site permissions or exceptions. Every mention of the user's profile folder appears as `%USERPROFILE%` (the whole page is masked, so the user name does not appear; added after the hands-on check found it in a check's detail).
- **Status:** Accepted by the product owner, 2026-11-23.

### D-048 — Fingerprint baseline: Google Chrome and bare WebView2 — **Accepted**
- **Context:** M8 measures how identifiable UNTRACE is. Microsoft Edge, the natural comparison (S1: WebView2's user-agent string equals Edge's), is not installed on the test machine.
- **Decision:** the same local fingerprint page runs in three browsers, all offline (a loopback test server):
  - Google Chrome, with a throwaway profile in a temporary folder, deleted afterwards (the user's own Chrome profile is not touched);
  - a bare WebView2 with default settings;
  - UNTRACE's real content host.
  Differences between bare WebView2 and Chrome show what marks WebView2. Differences between UNTRACE and bare WebView2 show what UNTRACE's own settings change.
- **Status:** Accepted by the product owner, 2026-11-24.

### D-049 — Fingerprinting measures: remove WebView2 tells, only where consistent — **Accepted**
- **Decision:** M8 evaluates removing what marks a page's host as WebView2, e.g. the "Microsoft Edge WebView2" client-hint brand and the inert `chrome.webview` object.
- **Rule:** a measure is adopted only if:
  - its result is the same in every place a page can look: the page, same- and cross-origin frames, a fresh `about:blank` frame, dedicated, shared and service workers, and the request headers;
  - its breakage is low.
  A lie that shows in one place but not another makes users more unique, not less. Randomizing canvas, audio or WebGL readouts ("farbling") is not evaluated in M8.
- **Status:** Accepted by the product owner, 2026-11-24.

### D-050 — Fuzzing: coverage-guided — **Accepted**
- **Decision:**
  - The parsers and validators that take outside input are fuzzed with cargo-fuzz (libFuzzer) on a nightly Rust toolchain: proxy request heads, settings files, block lists, cosmetic selectors, custom DoH servers, address rules, audit scrubbing, and the checks behind IPC arguments.
  - The product itself still builds with stable Rust; nightly is only a test tool.
  - Where cargo-fuzz cannot run reliably on Windows, the existing std-only randomized tests are extended instead, and that is recorded.
- **Status:** Accepted by the product owner, 2026-11-24.

### D-051 — Dependency review with cargo-deny and cargo-audit — **Accepted**
- **Decision:** cargo-deny (licences, sources, bans, advisories, per `deny.toml`) and cargo-audit (RustSec advisories) are installed on the development machine, and `scripts/check.ps1` runs them on every full check, as CI already does. `npm audit` already covers the UI.
- **Note:** cargo-deny's current release needs a newer rustc than the project's stable toolchain (1.94.1). It is built with the nightly toolchain; the project's own toolchain is unchanged.
- **Status:** Accepted by the product owner, 2026-11-24.

### D-052 — "Keep WebRTC inside the network layer": own switch, on — **Accepted**
- **Evidence (M8, `spikes/m8-fingerprint/RESULTS.md`):** with the network layer running, a page's WebRTC still sent STUN packets directly to a device address on the local network, and the engine looked the STUN server name up with plain DNS itself. That holds even with Strict encrypted DNS. WebRTC bypassed encrypted DNS, the network layer's malware/phishing check and local-network protection. Severity: high (it broke the stated promise of Strict mode and of local-network protection).
- **Mechanism:** the engine preference `webrtc.ip_handling_policy = disable_non_proxied_udp`:
  - With it: 0 packets, no plain DNS lookup, in normal and temporary (InPrivate) profiles.
  - The Chromium command-line switch for the same policy does not exist in the WebView2 runtime (no effect, measured).
  - UNTRACE writes the preference into the standard profile before the engine starts, and into each temporary profile's folder before the engine creates that profile (atomic edit, re-read; `engine_files::set_webrtc_policy`). It removes only the value it set.
- **Decision:** Settings › Network › "Keep WebRTC inside the network layer", **on** by default.
  - Applied whenever the network layer runs; a change takes effect at the next start (Scope::Environment).
  - Off, or with encrypted DNS off, the encrypted-DNS and local-network texts say that WebRTC is not covered.
  - Read back from the profile files before the engine loads them; exercised end to end by self-check 54 in a normal and a temporary tab.
- **Cost:** WebRTC connects only through the network layer (TURN over TCP/TLS, which most large call services offer). Direct peer-to-peer connections fail.
- **Status:** Accepted by the product owner, 2026-11-24.

### D-053 — Appearance: Black theme, accent colour presets, websites follow the theme — **Accepted**
- **Request:** the product owner asked for a darker look and other colours.
- **Decision** (Settings › Appearance):
  - **Theme:** System, Light, Dark or **Black** (true-black surfaces).
  - **Accent colour:** presets only: Grey (the neutral look, default), Blue, Teal, Green, Amber, Rose, Violet.
    - It colours the active tab, switches, segmented choices, primary buttons, progress and the focus outline.
    - Each preset has a shade for dark/black and one for light. A unit test checks every shade against every background in `tokens.css`: 3:1 for the control, 4.5:1 for text on it. The test also fails if those backgrounds change.
    - Status icons and the red reserved for danger never take the accent, so an amber or rose accent cannot read as a warning.
  - **"Websites follow this theme"** (on): pages are told UNTRACE's light/dark choice through the engine's supported `PreferredColorScheme` profile setting.
    - It applies to every profile, temporary ones included. With System, or with the switch off, pages follow Windows.
    - It is read back from the engine, and self-check 55 asks the page itself.
    - Forcing a dark look onto sites without one is not included: it exists only as an unsupported engine flag.
- **Privacy:** UNTRACE's own look is not visible to websites. The colour-scheme preference is, as in every browser.
- **Not included:** tinted themes and custom colours (not chosen).
- **Fixed after 1.0.0 (2026-11-25):** the product owner saw grey areas in the Black theme.
  - **Title bar:** Windows drew its own grey title bar. It now takes the theme's top-bar colour and text colour (`DwmSetWindowAttribute`), also when Windows switches between light and dark. Windows 10 keeps its own title-bar colour.
  - **Empty tab:** in dark mode the engine paints its blank page dark grey, whatever background UNTRACE sets. An empty tab the user opened now hides the page view, so the interface's own background shows. Pop-ups opened by pages are never hidden this way, because a page can write into its blank pop-up.
- **Status:** Accepted by the product owner, 2026-11-24.

### D-054 — M9 release checklist on the development PC — **Accepted**
- **Context:** M9's exit asks for the release checklist on a clean Windows 11 VM. This PC runs Windows 11 Home (no Hyper-V, no Windows Sandbox).
- **Decision (product owner, 2026-11-25):** run the checklist on this PC instead: install for the current user, first run, self-check, update, uninstall.
- **Not covered here:** a machine without the WebView2 Runtime (the installer's bootstrapper path), and a machine without development tools. These are listed as open in the release checklist and must be checked on a clean machine before a public release.
- **Status:** Accepted, 2026-11-25.

### D-055 — Bookmarks — **Accepted**
- **Request (product owner, 2026-11-25):** a bookmark feature, with a small button next to the address bar that opens them. Bookmarks were a candidate post-v1 item ("local only").
- **Decision (product owner, 2026-11-25):**
  - **Where:** a star in the address bar (and Ctrl+D, also inside pages) adds the page and opens it for editing; a button beside the address bar opens the bookmarks panel.
    - The panel slides in beside the page like the site and downloads panels. A drop-down over the page is not possible: the interface never draws over web content (D-021).
  - **Folders:** one level. Folders from another browser's nested folders are named by their path ("Bookmarks bar / Work").
  - **Import and export:** the standard bookmarks file (Netscape HTML) that Chrome, Edge and Firefox read and write. UNTRACE reads only the file the user picks; it never opens another browser's data on its own.
  - **Icons:** the icon the page showed when it was bookmarked, as a PNG of at most 16 KB. UNTRACE never fetches an icon. Imported bookmarks show the first letter of their site.
- **What is kept:** `config\bookmarks.json` on this computer only.
  - Only web addresses (http, https). `javascript:` bookmarklets, local files and engine pages are refused, also on import.
  - At most 10,000 bookmarks and 1,000 folders; titles are one line of at most 300 characters.
  - The file is validated on every start. A damaged file is set aside under another name, never deleted; a repaired one is kept as it was before the repair.
  - Bookmarks added from a temporary tab are kept too: adding one is an explicit choice, and the panel says so.
  - Deleting browsing data does not delete bookmarks; the panel has "Delete all bookmarks" with a confirmation.
- **Activity log:** imports, exports and "delete all" are recorded as counts. Addresses and titles never are.
- **Not included:** sync (out of scope), a bookmarks bar, bookmarks on the new-tab page (not chosen), drag and drop (Up and Down buttons instead).
- **Status:** Accepted, 2026-11-25.

### D-056 — Sleeping tabs — **Accepted**
- **Context:** the product owner asked how UNTRACE's memory use compares with Chrome, Brave and Edge. Measured on their running UNTRACE (2026-11-25): about 505 MB in 15 processes; 395 MB for pages (the same Chromium engine as those browsers), 91 MB for UNTRACE's interface (its own WebView2, separated from pages by design) and 19 MB for `untrace.exe` with every block list. Chrome's Memory Saver and Edge's sleeping tabs free background tabs; UNTRACE had nothing similar, so with many tabs it would use more.
- **Decision (product owner, 2026-11-25):** add sleeping tabs.
  - **Setting:** Settings › Performance › "Sleeping tabs": Off, 5 minutes, 30 minutes (default) or 2 hours in the background. Read back from the host's own sleep check, which runs every 30 seconds.
  - **How:** the engine's supported mechanism, as in Edge: the page's memory target is set to low (`ICoreWebView2_19::MemoryUsageTargetLevel`), then the page is suspended (`ICoreWebView2_3::TrySuspend`). Opening the tab resumes it and restores the normal memory target. A sleeping tab is dimmed in the tab bar.
  - **Never asleep:** the tab in view, tabs playing sound, tabs whose site may use the camera or microphone (allowed in that tab, or a saved permission), tabs waiting for an answer or showing a warning, loading or empty tabs.
- **Trade-off (in Settings):** a sleeping page does nothing until opened: no messages, notifications or updates; some pages reload or reconnect when they wake.
- **Not chosen:** sharing one engine between the interface and pages (about 60–80 MB less, but the interface would no longer be separated from web pages); turning off graphics acceleration (slower).
- **Status:** Accepted, 2026-11-25.

### D-057 — Ad blocking on hard sites: pop-up rules, uBlock Origin's lists and scriptlets — **Accepted**
- **Report (product owner, 2026-11-26):** on 9anime (`9anime.es`) ads, a "captcha" and tabs opening on every click kept appearing; YouTube showed video ads. Checked on the real sites with UNTRACE's own engine host (`examples/compat.rs adcheck`: real clicks through the engine's DevTools input, screenshots, the page's third-party requests).
- **Findings:**
  - A page's new window after a click was always opened: nothing checked its address.
  - The matching library (adblock-rust) does not know the `popup` option and drops every rule that names it: 2,977 rules in EasyList, the ones that stop ad pop-ups and pop-unders, with what such rules say about other types.
  - 9anime.es loads an ad network (Galaksion) whose script draws a fake captcha ("Bekräfta att du är människa", a cartoon face) in an invisible full-page frame that catches every click. EasyList does not list it. Two of three clicks opened an adult and a casino page.
  - uBlock Origin's lists do list it, but on Chromium with regular expressions that use lookahead, which the library cannot evaluate. The lists carry lookahead-free versions for Safari.
  - YouTube serves its video ads inside the player's data (`adPlacements`, `adSlots`, `playerAds`); blocking requests cannot remove them. uBlock Origin uses 40 scriptlet rules (12 scriptlets), and its quick fixes change every few hours.
- **Decision (product owner, 2026-11-26):** use uBlock Origin's rules, its scriptlet code included, as Brave does.
  - **Pop-up rules (UNTRACE):** rules naming `popup` are read by UNTRACE (`untrace-filter/src/popup.rs`) into a small engine of their own. A page's new window is refused if its address matches; so is a window that opens blank and is sent to a matching address within 15 seconds (pop-unders). Malware and phishing addresses are refused too. The site's "Block ads and trackers" switch turns ad pop-up blocking off there.
  - **uBlock Origin's lists:** filters, badware risks, privacy, quick fixes and unbreak (`ublockorigin.github.io/uAssets`), one Settings switch "uBlock Origin filters", on. Bundled for the first start, then updated like EasyList (quick fixes every 12 hours).
  - **Their `!#if` directives** are evaluated as uBlock Origin does on Chromium without HTML filtering (`preprocess.rs`). From Safari branches UNTRACE also takes the regular-expression network rules, and nothing else: they are the lookahead-free versions its engine can evaluate.
  - **Scriptlets:** uBlock Origin's own scriptlets, built from release 1.77.2 by `scripts/ubo-scriptlets` into `resources/ubo-scriptlets.json` (153 functions, 34 trusted) and bundled. A site's scriptlets go into the per-site script registered when a top-level navigation starts, so they run before the page's own scripts; they run once per document and only on that host. Only uBlock Origin's lists may use trusted scriptlets.
- **Measured after the change (same runner, same sites):**
  - 9anime.es: no fake captcha, no click-catching frame, no pop-up tab in three clicks (before: two); the ad network's scripts are blocked.
  - YouTube: no ad data in the player (`adPlacements` 0, `adSlots` 0, `playerAds` 0, before 1, 2–3, 1) and no ad shown; the video plays.
- **Not applied (counted, disclosed):** uBlock Origin options the library does not implement (`urlskip`, `denyallow`, `replace`, `uritransform`, `redirect-rule`, `cname`, `ipaddress`; about 5 % of uBlock Origin's rules, 16 % of its privacy list) and uBlock-only cosmetic syntax. Scriptlets run in the top-level document only, not in frames of other sites. `$document` rules of the badware list do not yet stop navigations with a warning page as uBlock Origin's strict blocking does.
- **Licence:** uBlock Origin's lists and scriptlets are GPL-3.0. They ship as separate data files with their licence text (`lists/LICENSE-uAssets.txt`, also installed beside the program). The legal review (D-017) must cover them.
- **Maintenance:** the scriptlets update only with UNTRACE. When uBlock Origin releases new scriptlets that its lists start to use, rebuild `ubo-scriptlets.json` (`node scripts/ubo-scriptlets/build.mjs <uBlock source> <tag>`) and release.
- **Supersedes:** D-043 (scriptlets deferred until the licence decision).
- **Status:** Accepted, 2026-11-26.
