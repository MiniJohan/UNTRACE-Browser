# UNTRACE — Architecture

Status: **Milestone 0 complete; Milestone 1 (foundation) implemented (2026-11-21).** M0 evidence: `spikes/M0-RESULTS.md`. Open product decisions: DECISIONS.md. Sections marked *(M1)* describe what is built; the rest is still design. Companion documents: FEASIBILITY.md (evidence), DECISIONS.md (rationale), THREAT_MODEL.md, SECURITY.md, TESTING.md, ROADMAP.md.

---

## 1. Principles → architectural rules

| Principle | Rule |
|---|---|
| Secure by default | Every protection ships with a safe default. No certificate-error bypass. Content has no path to privileged code. |
| Minimal by design | One window, one engine, four Rust crates, one small React UI. Every dependency is justified in DECISIONS.md. |
| Transparent by nature | Every protection reports a **verified** state (read back from the engine or proven by a self-test), not just the switch position. A data inventory says what is stored where. |
| User-controlled | Every protection is independently configurable, reversible and explained, including its limitations. |
| Local-first | No accounts, no sync, no telemetry. The only outbound traffic UNTRACE itself starts is filter-list updates, optional update checks and (optional) DoH queries — all listed in Diagnostics. |
| No silent system changes | UNTRACE reads Windows state; it never writes system-wide settings. |

---

## 2. System overview

```
┌──────────────────────── UNTRACE.exe  (Rust, standard user, never elevated) ───────────────────────┐
│                                                                                                   │
│  Tauri shell ─ window · single instance · capability-scoped IPC · signed updater                 │
│    │                                                                                              │
│    ├─ UI view          WebView2 environment "ui"       (trusted, bundled assets only)             │
│    │   React + TS: tab strip, address bar, panels, Settings, Diagnostics                          │
│    │        │  Tauri IPC — typed commands, UI window only                                         │
│    │        ▼                                                                                     │
│    │   ┌────────────────────────── Rust core ──────────────────────────┐                          │
│    │   │ untrace-core     settings · protection registry · storage ·   │                          │
│    │   │                  audit log · data inventory                   │                          │
│    │   │ untrace-webview  content environment · view manager ·         │                          │
│    │   │                  navigation & request policy · permissions ·  │                          │
│    │   │                  downloads · certificates · site data         │                          │
│    │   │ untrace-filter   adblock-rust engine · list manager ·         │                          │
│    │   │                  exceptions · cosmetic data                   │                          │
│    │   │ untrace-net      loopback proxy · DoH resolver ·              │  (conditional, M5)       │
│    │   │                  DNS diagnostics · connection view            │                          │
│    │   └───────────────────────────────────────────────────────────────┘                          │
│    │        ▲ COM events / calls (UI thread)                                                      │
│    └─ Content views    WebView2 environment "content"  (untrusted web; NO host bridge)            │
│                                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────────────────────┘
          │ COM                                                          ▲ CONNECT + proxy auth (loopback)
          ▼                                                              │
   msedgewebview2.exe — Microsoft Evergreen runtime: browser · network · GPU · sandboxed renderers
```

### 2.0 What Milestone 1 implements *(M1)*

- **Shell:** Tauri window. Refuses to start elevated; single instance; the window title stays "UNTRACE", so page titles never appear in the taskbar.
- **UI view:** navigation lock (refused attempts are counted in Diagnostics); new windows denied; context menu, browser shortcuts and zoom disabled in release builds.
- **Content views:** WebView2 controllers inside the UNTRACE container window, with:
  - tabs, navigation, titles, favicons (PNG only, ≤ 64 KB);
  - pop-ups only on a user click, opened as tabs;
  - shortcuts (Ctrl+L/T/W/Tab, Alt+D, F6) handled while a page has focus.
- **Hardening, read back by Diagnostics and the self-check:**
  - no host bridge;
  - password saving and autofill off;
  - SmartScreen off (D-012);
  - local crash reports;
  - history cleared at start.
- **Interim safe defaults until M2:**
  - every permission request is denied;
  - external-application launches are cancelled;
  - certificate errors are always cancelled (D-008).
- **Settings and diagnostics:**
  - protection registry with apply → read back → commit/revert;
  - one protection in M1 (developer tools, off);
  - settings validated on load;
  - URL-free audit log;
  - Diagnostics with configuration checks;
  - `--self-check` mode (TESTING §9).

### 2.0b What Milestone 2 adds *(M2)*

- **Navigation policy** (`untrace-core::policy` + `NavigationStarting`):
  - scheme gate (`file:`, internal pages);
  - HTTPS-only upgrade with loop guard and session exceptions (D-030);
  - hand-offs to other applications are not page loads;
  - completions are matched to their navigation by id.
- **Error panels** (HTTPS unavailable, certificate refused, load errors) are drawn by the UI while the page view is hidden. The engine's error pages are off (D-029).
- **Questions** go in a prompt bar above the page:
  - permissions (asked or refused by policy; optional per-site memory, listed and reset from the site panel);
  - other applications (abused link types refused; others asked each time);
  - downloads (question → Windows save dialog; programs flagged) (D-031).
- **Downloads panel:** session-only list.
- **Connection details** for valid HTTPS pages come from the engine's own verdict: each content view enables the DevTools protocol's `Security` domain (`Security.enable`, read-only, no page access) and listens for `Security.visibleSecurityStateChanged`. The site panel shows protocol, key exchange, cipher, subject, issuer and expiry only when the report's origin matches the page; otherwise it says nothing has been reported. This uses the host-side DevTools protocol, not the user-facing developer tools, which stay off.
- **Engine:** minimum WebView2 Runtime major version 130; "newer engine waiting" surfaced in Diagnostics.

### 2.0c What Milestone 3 adds *(M3)*

- **`untrace-filter`** (no unsafe code, no network): list catalog with bundled snapshots, header parsing, validation of downloads, the on-disk list store, and matching.
  - Ads and trackers (EasyList, EasyPrivacy): one adblock-rust engine, network rules only. Cosmetic rules wait for M6.
  - Malware and phishing: host sets. A listed host covers its subdomains, never its parent, so UNTRACE knows which list matched.
  - **Canaries:** every enabled list gets a rule for a reserved `*.canary.untrace.invalid` host. Settings reads each switch back by matching its canary; a cached engine is used only after every canary matches.
- **Content host** (`untrace-webview`):
  - Every view registers `WebResourceRequested` for its documents' requests (all resource types, frames included).
  - Exactly one live view, the **worker owner**, also registers shared/service-worker requests, which WebView2 raises on every registered view in the environment. When that tab closes, another tab takes over. This replaces the hidden sentinel view planned in §5.2 (D-034).
  - Blocked requests get an empty `403` created by UNTRACE. Pages see it as a failed load, like a blocked request in other blockers.
  - Malware/phishing pages are cancelled at `NavigationStarting`, before any connection, and replaced by UNTRACE's warning panel (D-033).
  - Counts and blocked hosts are kept per page, in memory only (D-014).
- **App:**
  - The filter service builds the filters at start (from the verified cache in milliseconds, otherwise about 0.1 s) before the first tab exists.
  - A combined applier routes the list switches; per-site exceptions are stored in Settings.
  - A background worker downloads due lists through WinHTTP (HTTPS only, TLS 1.2+, no cookies), validates them, keeps the previous copy, pre-builds the engine cache, and only then swaps the filters in on the UI thread.
  - The self-check never starts the updater.

### 2.0d What Milestone 4 adds *(M4)*

- **Tracking prevention** (D-035): a Settings choice (Off/Basic/Balanced/Strict, default Balanced). The content host keeps each profile object once its first tab delivers it, sets the level on every profile (standard and temporary), and reads it back from each.
- **Tracking parameters** (D-027): `untrace_filter::params` cleans an address at text level. In `WebResourceRequested`, a page or frame GET request carrying listed parameters is answered with a `307` to the cleaned address, so the server never receives them and the page's `location` is clean. The redirect restarts the navigation; the removed names are carried over to the new page's counts.
- **Temporary tabs** (D-036): tabs flagged `temporary` are created with an InPrivate profile named `temp-<random>` (D-028). One temporary profile is shared by all open temporary tabs and dropped when the last one closes. Each profile has its own worker-owner tab. Per-site blocking exceptions from temporary tabs live in memory only. Leftover temporary profile folders are removed at start, before the engine starts, after removing the engine's own record of those profiles from `Local State` (otherwise it reopens the last one, D-039).
- **Cookies and site data:** the standard profile's cookie manager (`ICoreWebView2Profile5`) lists cookies, grouped by site. Deleting a site deletes its cookies and clears storage for its origins through the DevTools protocol (`Storage.clearDataForOrigin`, host-side only), then reads the cookies back. "Delete all" and clearing on exit use the profile's `ClearBrowsingData`.
- **Start-up and exit** (D-038): the first standard tab clears history (and anything the previous session owed) before any page loads; navigations wait for it. Closing hides the window, clears what the exit switches ask for, verifies, records the result, then destroys the window. Crash reports older than 7 days are deleted at start (D-013).
- **Engine files at start-up** (D-039): before the engine starts, UNTRACE empties the per-site engagement lists in each profile's `Preferences` and removes temporary-profile entries from `Local State`. Each edit is parsed, written atomically and read back; unparseable files are left alone. Diagnostics shows the counts.
- **Data inventory:** a "Your data" page lists what UNTRACE and the engine store (§8), with sizes measured on disk, retention, and a delete button per category. The audit log records each deletion by category, never by site.

### 2.0e What Milestone 5 adds *(M5)*

- **`untrace-net`** (no new dependencies: standard-library threads plus Windows APIs):
  - the loopback proxy, with per-launch credentials and a random realm;
  - name resolution through `DnsQueryEx`, over HTTPS where possible;
  - local-address rules;
  - read-only DNS diagnostics;
  - a strict, bounded request-head parser, tested with 200,000 mutated inputs per run.
- **Start-up** (D-006, D-026): with Encrypted DNS on (Automatic by default, D-023), the shell starts the proxy before the engine. The engine gets only `--proxy-server=http://127.0.0.1:<port> --proxy-bypass-list=<-loopback>`. If the proxy cannot start, no page opens: UNTRACE fails closed and tells the user why.
  - When the first standard tab is ready, after the start-up clearing, UNTRACE sends a request from that tab to a random check name under `untrace.invalid`. The proxy never resolves such names. Navigations wait, at most 5 s, until the proxy has seen the request with this launch's credentials.
  - That check is the network layer's read-back ("Engine traffic goes through the network layer"). It also answers the proxy's one-time challenge before any page loads.
  - A completion with status 18 (proxy authentication) is never shown as a page error.
- **Credentials:** `BasicAuthenticationRequested` is answered only when the challenge carries this launch's random realm. A site's own sign-in request is left to the engine.
- **Resolver modes** (D-023, D-041):
  - *Automatic* uses DNS over HTTPS when a DNS server Windows uses has a known template (Windows' own list, or the adapter's setting); otherwise, or if that fails (counted), the Windows resolver answers.
  - *Strict* uses only the chosen provider, never falls back, and resolves nothing if no server is set.
  - Local names always go to Windows. Answers are cached in memory within their TTL (30 s – 5 min).
- **Backstop** (D-042): the proxy refuses hosts on the enabled malware/phishing lists (shared with the request layer through `Filters::shared_threats`), except hosts the user continued to this session.
- **Local-network protection** (D-040):
  - The request layer gives an empty 403 to requests from a public page to loopback or local addresses and local names, unless the site is allowed.
  - Pages that may reach the local network, and every top-level navigation, *announce* public names to the proxy.
  - The proxy refuses public names that resolve locally unless announced, and always once the name resolved publicly earlier in the session (rebinding).
- **Records:** per-host counts (connections, refusals, failures, how the name was resolved), memory only, capped at 2,000 hosts. They feed the site panel's "Route" line, error panels ("Encrypted DNS (Quad9) did not answer…"), the connection view in Diagnostics, and the data page.

### 2.0f What Milestone 6 adds *(M6)*

- **`untrace_filter::cosmetic`** sorts the enabled Adblock lists' hiding rules:
  - generic rules by class or id (97 % of EasyList's), other generic rules, site-specific rules, exceptions, and `$generichide`/`$elemhide` sites;
  - extended rules, rules with actions and scriptlets are only counted (D-043, D-044);
  - selectors are refused if they contain `{`, `}`, `/*` or a leading `@`, so no declaration can be smuggled in;
  - each list adds canary rules.
- **Two scripts** (D-015 vehicle a3). The per-document cost is proportional to script size (about 1 ms per 100 KB per document), so the data is split:
  - `CosmeticRules::script` (every document, about 0.23 MB) carries the generic rules and the exceptions that unhide them. At document start in every frame, it finds the host by `self.origin` (so `about:blank` frames inherit their parent's) and applies other-generic rules through one adopted stylesheet.
  - `site_script(host)` (about 1 KB) carries only the visited site's own rules. It is registered when a top-level navigation starts. If the registration completes too late for the new document, it is run once more when content starts loading, and a marker (`Symbol.for("untrace.cosmetic.site")`) keeps it from applying twice. Frames from other sites get only the generic rules.
  - A `MutationObserver` adds the generic rules of each class and id as it first appears on the page.
  - No request and no bridge, and nothing page-visible beyond the adopted stylesheets.
  - Sites the user excepted, and `$elemhide` sites, get nothing.
- **Host:** the generic script is registered once per tab (`AddScriptToExecuteOnDocumentCreated`); a new tab waits for it, at most 3 s, before its first page. Both scripts are regenerated on list, switch or exception changes, and per-tab generation counters remove any registration that completes after being superseded.
- **Cost:** the first, single 0.84 MB script cost about 4.4 ms per document and measured load-event p95 +12 % on real sites. The split costs +6 ms for 9 documents on the spike page (+77 ms before) and about 4 % typical on real sites; the p95 was not settled on a noisy network (`spikes/m6-cosmetic/RESULTS.md`).

### 2.0g What Milestone 7 adds *(M7)*

- **Self-check from the app** (D-046): Diagnostics starts `untrace.exe --self-check <data root>\self-check\report.json` as a separate process. It has its own window, its own data folder and no network, and it never touches the user's profile.
  - `selfcheck::COVERAGE` maps each protection to the checks that exercise it; a unit test requires one for every protection in Settings.
  - The report carries a per-protection result, which Diagnostics and Settings show.
- **New self-checks** for the last protections without one: the update switch (one tick of the updater with the switch off makes no attempt), clearing on close (`privacy::exit_clear_run`, the routine the close uses, run without closing), and the Strict provider's honest *not verified* path.
- **Activity log page:** every entry (current and rotated file), filter by kind, export through the Windows save dialog, clear.
- **Security report** (`report.rs`, D-047): one HTML file with a strict CSP and no scripts. It covers protections, checks, the self-check, lists, DNS setup and a log summary; it never contains browsing data.
- **Update status:** engine, lists, and the app itself (not available until M9).

### 2.0h What Milestone 8 adds *(M8)*

- **WebRTC inside the network layer** (D-052): `engine_files::set_webrtc_policy` writes `webrtc.ip_handling_policy = disable_non_proxied_udp` into the standard profile's `Preferences` before the engine starts, and into each temporary profile's folder when its session begins. It is written only while the network layer runs and the switch is on, and it is removed when either is off (only the value UNTRACE set). Self-check 54.
- **Fingerprinting evaluation** (D-011, D-048, D-049): a local harness (`spikes/harness m8`, `spikes/m8-fingerprint`) compares Chrome, bare WebView2 and UNTRACE in every context a page can use. No measure was adopted.
- **Fuzzing** (D-050): `fuzz/` (cargo-fuzz, its own workspace) has targets for every parser and validator that takes outside input. The campaign found one bug: the proxy forwarded a lone CR or LF inside a header line. `http::parse` now refuses it.
- **Dependency checks** (D-051): cargo-deny and cargo-audit run in every full check. `deny.toml` allows the workspace's own path dependencies (`allow-wildcard-paths`).

### 2.0i What Milestone 9 adds *(M9)*

- **Installer** (`tauri.conf.json` › `bundle`): per-user NSIS, no administrator rights. It carries Microsoft's WebView2 bootstrapper for machines without the engine, plus the licence and the third-party notices. The uninstaller's "Delete the application data" option also removes `%LOCALAPPDATA%\UNTRACE` (`installer-hooks.nsh`).
- **Updates** (`appupdate.rs`, D-016): §9. Self-check 56 exercises the updater's own signature check offline: a correct update, one changed by a single bit, a foreign key, and a signature made for another version.
- **Release process** (`scripts/release.ps1`, `RELEASING.md`): the full check, the installer with its update signature, `latest.json` and checksums. A release cannot be built without the update key and the release address.
- **First start and About:** one welcome screen; Settings › About shows the version, the MPL-2.0 licence, the privacy notice (`PRIVACY.md`, compiled in) and the third-party notices (`scripts/notices`, kept in step by the full check).

### 2.1 Why two layers of webview

- **UI view** (Tauri-managed): renders UNTRACE's own interface from bundled files. It is the only place Tauri IPC exists.
- **Content views** (created by `untrace-webview` through the WebView2 COM API, crate `webview2-com`): render the web. Each is parented to an UNTRACE-owned child window kept above Tauri's own webview in z-order; parented directly to the Tauri window, the content view ends up hidden behind it (S1). They have no Tauri scripts, no custom protocols, no host objects and no web-message channel. The inert `chrome.webview` object remains visible to pages regardless (S1). A compromised page can talk to UNTRACE only through what the WebView2 runtime itself reports as events (URLs, headers, permission requests, downloads), and all of that is treated as untrusted input.

See DECISIONS D-002 and D-003.

### 2.2 Threading

- WebView2 requires a single-threaded apartment. All WebView2 calls and event handlers run on Tauri's main (UI) thread.
- Filter matching happens synchronously in `WebResourceRequested` on that thread. adblock-rust matching is designed to be fast; the budget is ≤ 0.2 ms p99 per request (measured in S2).
- Engine rebuilds, list downloads, the proxy and DoH run on a small Tokio runtime. Results are posted back to the UI thread; the filter engine is swapped atomically between requests.
- The UI never blocks on network or disk.
- **Shutdown:** every WebView2 object (controllers, environment, download operations, deferrals) is released when the main window is destroyed, while the event loop and the engine's threads still run. Nothing WebView2-related may be left for thread-local or static teardown: inside `ExitProcess` that release blocks forever (M2 finding; guarded by the clean-exit step in `scripts/check.ps1`).

---

## 3. Components

### 3.1 Tauri shell (`app/src-tauri`)
- Single window, custom title bar drawn by the UI view (Windows snap layouts preserved).
- Plugins: `single-instance`, `updater`. Nothing else (no `fs`, `shell`, `http` plugins).
- Capabilities: one capability file granting UNTRACE's own commands to the window label `main` only. No `remote` URLs. `withGlobalTauri` off.
- Refuses to start elevated (WebView2 behaves differently when elevated, and a browser must never run as admin).
- Tauri version pinned to ≥ 2.12.7 (current stable, verified in S1; ≥ 2.11.1 is required for CVE-2026-42184).

### 3.2 UI (`app/ui`, React + TypeScript + Vite)
- Dependencies: `react`, `react-dom`, `@tauri-apps/api`. Dev: `vite`, `typescript`, `@vitejs/plugin-react`. No component library, CSS framework, router or state library.
- Strict CSP: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src ipc: http://ipc.localhost; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'`.
- Navigation away from the app origin is refused by the shell.
- Untrusted strings from content (titles, URLs, filenames) are rendered as text only. Favicons arrive as size-limited, re-encoded data URLs produced in Rust; the UI never fetches remote resources.

**Design system** (implements the product's design philosophy):
- Grayscale tokens on `:root`, dark-first, with Light and Black themes (D-053). By default no accent colour is used: state is shown with weight, contrast and iconography, plus a restrained red reserved for danger (certificate errors, malicious-site block). The user may choose an accent preset (D-053). It colours controls only, never status icons or danger, and falls back to the neutral tokens when unset (`--accent-dark`/`--accent-light` set on the root by the app).
- Type: Segoe UI Variable (the Windows system face), 3 sizes, 2 weights.
- Spacing: 4 px grid. Hairline borders (1 px, low-contrast). No gradients, no shadows beyond one subtle elevation level.
- Motion: 120–200 ms ease-out for panel and state transitions; respects `prefers-reduced-motion`.
- No "security score". Status is factual: *On · verified*, *On · not verified (reason)*, *Off*, *Error (reason)*.

**Layout** (respects the airspace limitation, FEASIBILITY L9):
- Top bar: tabs + navigation + address field + site-status button + menu.
- Side panel (site info, permissions, blocked requests) slides in from the right and **resizes** the content view; it never overlaps it.
- Settings and Diagnostics open as full pages that temporarily hide the content view.
- Address-field suggestions (if any) appear in an owned popup window above the content area. v1 shows no remote suggestions.

### 3.3 `untrace-core`
- **Protection registry** — the single source of truth for every user-facing protection (§6).
- **Storage** — versioned JSON files written atomically (temp file + rename), validated on load. Invalid or tampered files are backed up and replaced by defaults, and the user is told.
- **Audit log** — append-only, size-capped, local; records configuration changes, protection state changes, list updates, update checks, self-test results and errors. **Never records URLs or page content.**
- **Data inventory** — computes what is stored and where (§8) for the Diagnostics page.

### 3.4 `untrace-webview`
- Creates the content environment (§4) and profiles; creates, positions and destroys content controllers as children of the Tauri window's HWND.
- Owns the navigation policy (§5.1), request policy (§5.2), permission manager, download manager, certificate handling, external-scheme prompts, pop-up handling (`NewWindowRequested` → new tab in the same profile, preserving `opener` for sign-in flows), keyboard accelerators (`AcceleratorKeyPressed` so Ctrl+L/T/W work while content has focus), favicons and titles.
- Holds per-tab, in-memory transparency counters (blocked/allowed third-party hosts). Discarded when the tab closes.

### 3.5 `untrace-filter`
- Wraps adblock-rust. Builds an engine from enabled lists + UNTRACE's internal rules (canary rules on reserved `.invalid` names, M3). Resources (scriptlets/redirects from a bundled, pinned uBlock Origin resource set) arrive with M6 and D-017; until then a `$redirect` rule blocks without substituting.
- **List manager** *(M3)*: bundled baseline lists (offline first run), HTTPS updates when each list's `Expires` says so, validation (size cap 16 MB, UTF-8, expected `Title:`, minimum rule count, parse-error ratio, no shrinking below a per-list fraction of the previous version), the previous copy kept and used if the current one is damaged (checksums), a serialized engine cache keyed by adblock-rust version + inputs and verified by canaries after loading.
- **Exceptions** *(M3)*: per-site (registrable domain) switch for ads/trackers blocking. Malware/phishing warnings are not affected. *Cosmetic only off* arrives with M6.
- **Trusted scriptlets** are only allowed for lists UNTRACE marks as trusted (permission masks); a compromised list can only invoke existing, bundled scriptlets — never ship code.

### 3.6 `untrace-net` *(M5; S3 passed)*
- **Loopback proxy**: HTTP proxy on `127.0.0.1:<random port>`, supporting `CONNECT` tunnels (HTTPS, WSS) and absolute-form plain HTTP forwarding (HTTP exceptions and loopback). Plain HTTP is forwarded once per connection with `Connection: close`, without proxy and hop-by-hop headers. Requires per-launch random credentials supplied to WebView2 through `BasicAuthenticationRequested`; other local processes get `407`. Limits: 16 KB request head, 100 headers, 15 s to send it, 1,024 open connections; one thread per connection direction (Chromium opens at most 32 connections per proxy, plus WebSockets).
- **No TLS interception, ever** (D-007). The proxy sees host names and ports, never content.
- **Resolver** (proxy on): *System* (the proxy resolves through the Windows DNS client, which honours Windows' own DoH settings), *Automatic* (DoH if the system's configured server has a known DoH template, otherwise system), or *Strict DoH* with a chosen provider (no fallback; resolution fails if DoH fails). Implementation: Windows 11 native `DnsQueryEx` with a DoH custom server — verified in S3, no resolver crate (D-024). With the network layer **off**, WebView2 resolves names itself with Chromium's built-in DNS client ("Automatic" secure DNS; unencrypted on most networks) and performs WPAD lookups (S3).
- **Network backstop** (D-042): malware/phishing hosts refused for connections the request layer cannot see (WebSockets, runtime traffic), honouring the session's "Continue anyway". No permanent allow-list (D-033).
- **DNS-rebinding guard** (D-040): see §2.0e.
- **Connection view**: in-memory list of host names contacted this session. The proxy cannot tell which tab a connection belongs to, so it separates pages (with credentials) from the runtime's own background traffic (never authenticated, refused, D-025).
- **Fail closed**: if the proxy stops answering, page loads fail and nothing goes direct (S3; self-check 43). If it cannot start, no page opens.
- **DNS diagnostics** (read-only, available even without the proxy): active adapters, configured DNS servers, whether Windows encrypts queries to them (per-interface DoH settings), the resolver UNTRACE uses, and live DoH/system lookup counters.

---

## 4. WebView2 configuration

### 4.1 Environments

| | "ui" environment | "content" environment |
|---|---|---|
| Created by | Tauri (wry) | `untrace-webview` (`webview2-com`) |
| User data folder | `%LOCALAPPDATA%\UNTRACE\ui` | `%LOCALAPPDATA%\UNTRACE\content` |
| Loads | Bundled UI assets only | The web |
| Browser arguments | None | Only `--proxy-server=http://127.0.0.1:<port> --proxy-bypass-list=<-loopback>` when the network layer is on (M5) |
| Tracking prevention | Off (local content) | On (`EnableTrackingPrevention = true`) |
| Extensions | Off | Off (unless D-015 selects the extension vehicle) |
| Crash reporting | Custom (local) | Custom (local) — `IsCustomCrashReportingEnabled = true` |

Two environments mean two browser-process groups, about 120 MB of extra private memory (M1 experiment). One shared environment would avoid that, but Tauri 2.12 cannot enable WebView2's custom crash reporting for the environment it creates, so sharing would break D-013. D-003 records when to revisit.

### 4.2 Profiles (content environment)

| Profile | Mode | Purpose |
|---|---|---|
| `standard` | Persistent | Default browsing. Cookies persist (so sign-ins work) unless *clear on exit* is enabled. |
| `temp-<random>` | InPrivate | Temporary session. Each temporary window/tab group gets its own; data discarded when it closes. |

### 4.3 Content view settings

| Setting | Value | Why |
|---|---|---|
| `AreHostObjectsAllowed` | false | No host bridge |
| `IsWebMessageEnabled` | false | No host bridge |
| `AreDevToolsEnabled` | false (user toggle) | Reduces social-engineering surface; developer toggle in Settings › Advanced |
| `IsPasswordAutosaveEnabled` / `IsGeneralAutofillEnabled` | false | Avoid storing secrets/personal data in the engine |
| `IsReputationCheckingRequired` | per D-012 (default proposed: off) | SmartScreen sends data to Microsoft |
| `IsStatusBarEnabled` | true *(M1)* | The engine's status bar shows link targets until UNTRACE shows them itself (M2) |
| `AreDefaultContextMenusEnabled` | true, filtered via `ContextMenuRequested` | Remove items that bypass UNTRACE (e.g. "open in new window" outside policy) |
| `IsBuiltInErrorPageEnabled` | false *(M2)* | UNTRACE's own panels (D-029); the engine's pages could offer unsafe ways to continue |
| User agent | Unchanged | Overriding clears UA client hints and increases uniqueness |

---

## 5. Policy pipelines

### 5.1 Navigation policy (`NavigationStarting`, frame `NavigationStarting`)

```
1. Scheme gate      https ✓ · http → step 3 · about:blank ✓ · blob/data (engine-governed) ✓
                    file:, edge:, chrome:, view-source:, javascript: (typed) ✗
                    other schemes → LaunchingExternalUriScheme → explicit user prompt, never remembered by default
2. Malicious check  engine + malicious lists → UNTRACE interstitial (source list named; "go back" default)
3. HTTPS-only       http://… → cancel, navigate https://…; on failure → UNTRACE page with
                    "continue over HTTP for this site (this session)" — never automatic
4. Param cleanup    GET top-level/frame navigations: engine $removeparam + built-in list → cancel, re-navigate clean URL
5. Allow            record top-level site for the tab (used by request policy and exceptions)
```

### 5.2 Request policy (`WebResourceRequested`)

- Filters registered with `AddWebResourceRequestedFilterWithRequestSourceKinds` when each view is created, before its first navigation: document sources on every view; service/shared-worker sources on exactly one live view, the worker owner (D-034; worker requests are raised for every matching view in the environment).
- For each request *(M3)*: top-level document → skipped (checked at `NavigationStarting`) · host on a malware/phishing list and not continued to this session → **block** · tab's site excepted → allow · ads/trackers engine match (URL, page URL, resource type) → **block** (UNTRACE-created empty `403`) · otherwise **allow** (no response set; the runtime continues normally). **Redirect** (bundled neutered resource) arrives with M6.
- Worker requests carry no tab; they are matched with their `Referer` (or their own URL) as the page, and counted per session, not per page (documented limitation).
- The internal endpoint for cosmetic data (if vehicle (a) is chosen) uses a reserved `https://<token>.untrace.invalid/` host that is answered locally and never reaches the network.

### 5.3 Cosmetic filtering (M6; vehicle chosen in S4 → D-015)

Scripts registered with `AddScriptToExecuteOnDocumentCreated` and regenerated whenever the filter lists, the switch or a site exception change carry the cosmetic data themselves. One, in every document, holds the generic rules keyed by class and id, other generic rules, and the exceptions. A second, registered per top-level navigation, holds the visited site's own rules. At document start, in every frame, the rules for the frame's origin are applied through `document.adoptedStyleSheets`; generic rules keyed by class or id are added as those appear (observed). Built in M6 (§2.0f).

S4 showed this is the only tested vehicle that works on strict-CSP pages and in cross-origin frames, before first paint, with no CSP violations. Fetching rules at runtime, per-navigation registration, DevTools isolated worlds and extensions each failed one of those tests.

Budget: EasyList + EasyPrivacy carry ~190 KB generic + ~480 KB site-specific data. M6 measured the cost as proportional to script size, which is why the site-specific data is no longer in every document. Scriptlets need the page's main world and run only from the bundled resource set; they ship after CSS hiding is stable.

---

## 6. Settings model

Every protection is a registry entry:

```rust
struct Protection {
    id: &'static str,          // "filter.ads", "privacy.https_only", …
    title, explanation, limitations: &'static str,
    scope: Scope,              // App | Environment (restart) | Profile | View
    default: State,
    apply: fn(&State) -> Result<(), ApplyError>,
    observe: fn() -> Observed, // Verified(state) | Unverifiable(reason)
    self_test: Option<SelfTest>,
}
```

**Change flow:** user toggles → write *pending* → `apply` → `observe` → if observed == requested: commit + audit entry; else: revert to previous state, show the error, audit entry. Environment-scoped changes are marked *applies after restart* and are verified after the restart.

**Verification sources:** engine read-back (tracking-prevention level, permission settings, SmartScreen flag, browser version), UNTRACE state (filter rule counts, list versions, proxy counters), and **self-tests** — local test pages on reserved `.invalid` hosts answered by UNTRACE that exercise a protection end-to-end (e.g. a request matching an internal test rule must be blocked; an `http://` navigation must be upgraded). Self-tests make no external network requests.

**Proposed defaults** (several are open decisions — see DECISIONS.md):

| Protection | Default | Scope |
|---|---|---|
| Ad blocking (EasyList) | On | View (live) |
| Tracker blocking (EasyPrivacy) | On | View |
| Malicious-domain filtering | On | View (+ network layer) |
| Cosmetic filtering | On once shipped | View |
| Edge tracking prevention | Balanced (Strict optional) | Profile |
| Third-party cookie restriction | Per S6 outcome | Profile |
| Tracking-parameter cleanup | On | View |
| HTTPS-only | On | View |
| Certificate errors | Always block (not configurable in v1) | — |
| Permissions | Ask for camera, microphone, location, notifications; deny others | Profile |
| Downloads | Ask where to save; warn on executable types | Profile |
| SmartScreen | **Open decision** (proposed: off) | Environment |
| Encrypted DNS | **Open decision** (proposed: Automatic) | Environment |
| Fingerprinting reduction | Standard (lists + tracking prevention); M8 adopted no script-level measure (D-011) | View |
| Keep WebRTC inside the network layer | On (D-052) | Environment |
| Theme, accent colour | System, Grey (D-053) | UI only |
| Websites follow the theme | On (D-053): engine `PreferredColorScheme` per profile | Profile |
| Clear on exit | History + cache: on; cookies: off | Profile |
| Developer tools | Off | View |
| Update checks | **Open decision** | App |

---

## 7. Diagnostics

| Section | Content | Source |
|---|---|---|
| Engine | WebView2 runtime version, channel, pending update, minimum-version check, detected WebView2 policies | API + read-only registry |
| Protections | Each protection's observed state, last verification, self-test result | Registry `observe` + self-tests |
| Filter lists | Name, source, version/timestamp, rules, last update, next update, errors | List manager |
| DNS | Adapters, DNS servers, Windows DoH status, UNTRACE resolver, counters | Read-only Windows APIs + proxy |
| Network (if enabled) | Proxy status, port, auth active, connections this session, runtime/background hosts | `untrace-net` |
| Configuration checks | Not elevated, data folders ACL-private to the user, config schema valid, no unexpected browser arguments in effect, crash reporting local | Local checks |
| Updates | App version, last check, available update, signature status | Updater |
| Local security audit | Runs all of the above + self-tests, produces a short local report (copyable text, never sent) | All |
| Audit log | View, export, clear | `untrace-core` |
| Data inventory | What is stored, where, how much, retention, one-click clear per category | §8 |

---

## 8. Data storage and retention

Root: `%LOCALAPPDATA%\UNTRACE` (Local, not Roaming — browsing data must not roam).

The per-user installer (M9) puts the program in the same folder, the installer's default: `untrace.exe`, `uninstall.exe` and `THIRD-PARTY-NOTICES.txt` at the top, the data in the subfolders below.
- UNTRACE never deletes the whole folder, only subfolders.
- The uninstaller removes only the files it installed. It removes the folder only when the user ticks "Delete the application data" (`installer-hooks.nsh`), and never during an update.

| Data | Location | Retention | Notes |
|---|---|---|---|
| Settings | `config\settings.json` | Until changed | Protection states, preferences |
| Site exceptions | `config\exceptions.json` | Until removed | **Reveals sites the user chose** — shown and clearable |
| Filter lists, engine cache | `lists\` | Replaced on update | Public data |
| Audit log | `logs\audit.log` | 2 × 512 KB rotating | No URLs or content |
| Standard-profile web data | `content\` (WebView2) | Cookies and site data until deleted (per site, all, or on every exit); cache deleted on exit by default; history and download history cleared at the start of every session (D-038) | WebView2 keeps internal history (M0/S5); UNTRACE has no history UI. The engine also keeps per-site engagement scores that none of its delete functions remove; UNTRACE empties them at every start, before the engine runs (D-039) |
| Exit-clearing record | `config\exit-clear.json` | Replaced each session | Pending/done/failed and what was owed; no sites |
| Temporary sessions | In memory (InPrivate) | Until the last temporary tab closes | Residue checked by self-check 23; an almost empty profile folder is removed at the next start |
| Permission decisions | WebView2 profile | Until reset | Listed via read-back API |
| Crash dumps | `content\EBWebView\Crashpad\reports` | Deleted after 7 days (at start) or on demand on the data page; **never uploaded by UNTRACE** | Can contain page memory — sensitive |
| UI webview data | `ui\` | Minimal | No remote content ever loaded |
| Connection view, per-tab counters | Memory | Session / tab lifetime | Never written to disk |
| Downloads | User-chosen folder | User-owned | — |

UNTRACE stores no browsing history of its own, no session restore by default, no analytics, no identifiers.

---

## 9. Updates

| What | Mechanism | Privacy | Integrity |
|---|---|---|---|
| WebView2 engine | Microsoft Evergreen updater | Microsoft's update traffic (outside UNTRACE) | Microsoft-signed |
| UNTRACE app | Tauri updater (`tauri-plugin-updater`, Windows TLS): `latest.json` on GitHub Releases, checked once a day while "Check for UNTRACE updates" is on (D-016). An update is shown, never installed by itself. | One HTTPS request per day to GitHub; no identifiers added | Ed25519 signature checked before the installer runs, bound to the announced version (`requireSignedVersion`: no downgrade to an older signed release). Authenticode: not yet (D-016) |
| Filter lists | Direct HTTPS from each list maintainer | Reveals the user's IP to maintainers; disclosed | TLS + validation + last-known-good rollback (no upstream signatures exist) |

`NewBrowserVersionAvailable` → non-intrusive "restart to update engine" notice. UNTRACE refuses to start below a minimum runtime version that provides the APIs it depends on.

---

## 10. Windows integration boundaries

- Per-user install (NSIS, current user), **no admin rights**.
- Writes only inside `%LOCALAPPDATA%\UNTRACE`, the user's chosen download folder, and its own install folder.
- **Read-only** Windows queries: network adapters and DNS servers, per-interface DoH settings, WebView2 and SmartScreen policy keys, OS version, elevation state.
- No changes to system DNS, proxy, hosts file, firewall, certificates, policies or default-browser registration in v1. Registering as default browser (a user-level setting) could be added later as an explicit, reversible action.

---

## 11. Dependencies (planned)

| Rust crate | Purpose |
|---|---|
| `tauri` (≥ 2.12.7), `tauri-build`, `tauri-plugin-single-instance`, `tauri-plugin-updater` | Shell, IPC, packaging, updates |
| `webview2-com`, `windows` | Content views, Windows APIs |
| `adblock` | Filtering engine |
| `tokio`, `hyper`, `hyper-util` | Proxy, list downloads |
| `rustls` (via `hyper-rustls`) | TLS for list downloads and DoH |
| `serde`, `serde_json`, `url`, `thiserror` | Storage, parsing, errors |

Policy: no crate added without a DECISIONS entry; `cargo deny` (licences, advisories, duplicates) and `cargo audit` in CI; lockfiles committed; npm dependencies limited to the list in §3.2.

---

## 12. Repository layout (proposed)

```
untrace/
├─ ARCHITECTURE.md  DECISIONS.md  FEASIBILITY.md  ROADMAP.md  SECURITY.md  TESTING.md  THREAT_MODEL.md
├─ Cargo.toml                 workspace
├─ crates/
│  ├─ untrace-core/
│  ├─ untrace-filter/      (M3)
│  ├─ untrace-net/         (M5)
│  └─ untrace-webview/
├─ app/
│  ├─ src-tauri/              shell, commands, capabilities/
│  └─ ui/                     React + TS
├─ assets/
│  ├─ lists/                  bundled baseline lists + LICENSES
│  └─ resources/              pinned scriptlet/redirect resources + LICENSE
├─ tests/
│  ├─ fixtures/               local test sites (served by test harness)
│  └─ integration/
├─ scripts/check.ps1          local checks = CI checks
├─ .github/workflows/ci.yml
├─ deny.toml  rustfmt.toml
└─ spikes/                    Milestone 0 experiments (not shipped)
```
