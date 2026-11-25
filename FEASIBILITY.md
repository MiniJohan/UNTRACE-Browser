# UNTRACE — Technical Feasibility Report

Date: 2026-11-21 · Status: **For review** · Scope: architecture research only, no product code written.

---

## 0. Milestone 0 outcome (2026-11-21)

The six spikes ran on this machine (runtime 157.0.4341.60, Tauri 2.12.7). Full results: `spikes/M0-RESULTS.md`.

- **Confirmed:**
  - Request interception covers every tested type except WebSockets.
  - The loopback proxy carries all page traffic, leaks no DNS and fails closed.
  - The Windows native DoH API works.
  - Temporary sessions leave no page data on disk.
  - Downloads get Mark-of-the-Web.
  - Tracking prevention Strict blocks known trackers and can be verified by read-back.
  - Cosmetic filtering works on strict-CSP pages and in cross-origin frames.
  - Content views carry no Tauri globals.
- **Changed:**
  - Content views must sit in an UNTRACE container window, because Tauri's webview otherwise covers them.
  - Third-party cookies get no "block all" setting: the DevTools route works per view only.
  - The resolver crate is dropped in favour of the OS DoH API.
- **Confirmed limitations:**
  - WebView2 is identifiable: a "Microsoft Edge WebView2" client-hint brand, and `chrome.webview` is always present.
  - WebSockets are visible only to the proxy.
  - Interception costs ~0.17 ms per request.
- **Still pending:** real-site page-load overhead (needs approval to visit real sites), manual DPI/IME/focus checks.

---

## 1. Verdict

The proposed stack (**Tauri 2 + React/TypeScript UI + Rust core + Microsoft Edge WebView2**) is viable for UNTRACE's scope. It needs **one structural change** and comes with **five limitations** that must be documented, not hidden.

**Structural change.** Web content must **not** be hosted in Tauri-managed webviews. Tauri injects its IPC bridge (`__TAURI_INTERNALS__`) and registers custom protocols in every webview it creates, and multi-webview support is still behind Tauri's `unstable` feature flag. Instead, content views are created directly against the WebView2 COM API (Rust crate `webview2-com`) inside a **separate WebView2 environment with no host bridge at all**. Tauri is kept for what it is good at: the window, the trusted UI, capability-scoped IPC, packaging and signed updates.

**Limitations WebView2 imposes (cannot be engineered away):**

| # | Limitation | Consequence for UNTRACE |
|---|---|---|
| L1 | No API to block third-party cookies | Only partial restriction (Edge tracking prevention, filter lists, cleanup). An experimental DevTools-protocol route needs a spike. The setting must be labelled honestly. |
| L2 | No API for encrypted DNS (DoH) | App-scoped DoH is only possible via a local loopback proxy that WebView2 is pointed at with the `--proxy-server` browser flag. |
| L3 | Microsoft states browser flags should not be used in production | L2's solution depends on a flag. It must be verified at runtime, fail closed, and have a fallback (diagnostics only). |
| L4 | No engine-level anti-fingerprinting; WebView2 is likely more identifiable than stock Edge | Only modest "fingerprinting reduction" can be claimed. No anonymity claims. |
| L5 | Microsoft's runtime sends *required* diagnostic data the app cannot disable | Must be disclosed. UNTRACE can disable SmartScreen and keep crash dumps local, but not more. |

**Everything else in scope** — ad/tracker/malicious-domain filtering, tracking protection, HTTPS-only, certificate enforcement, permissions, downloads, temporary sessions, cookie and site-data management, diagnostics — maps to documented WebView2 APIs or to logic UNTRACE owns.

**Recommendation:** run Milestone 0 (six time-boxed feasibility spikes with explicit go/no-go gates, see §7 and ROADMAP.md) before writing product code. If the gates fail, the fallback path is in §6.

---

## 2. Development environment (inspected 2026-11-21)

| Component | Found | Assessment |
|---|---|---|
| OS | Windows 11 Home, build 26300, x64 | OK. Build 26300 appears to be a preview build; also test on a GA build before release. |
| CPU / RAM | Ryzen 5 3600, 32 GB | Ample for Rust + WebView2 development. |
| WebView2 Runtime | Evergreen **157.0.4341.60** (machine-wide) | OK. Recent enough for every API referenced in this report (exact SDK minimums pinned in M0). |
| Rust | rustc / cargo 1.94.1, `stable-x86_64-pc-windows-msvc` | OK. |
| MSVC | Visual Studio 2022 Community with VC x64 tools | OK (found via vswhere; `cl`/`link` not on PATH, which is normal — cargo locates them). |
| Windows SDK | 10.0.26100.0 | OK. |
| Node.js / npm | 24.18.1 / 11.16.0 | OK for Vite + React + TypeScript. |
| git | 2.55.0 | OK. The working folder is not a repository yet. |
| .NET SDK | present | Not needed. |
| Not installed | Tauri CLI, `cargo-audit`, `cargo-deny`, `gh` | Tauri CLI goes in as a project dev-dependency at M1; audit tools at M1. |

Read-only observation: Windows lists its built-in table of known DoH servers (`Get-DnsClientDohServerAddress`); whether any adapter actually enforces DoH was not changed or probed further.

---

## 3. Browser engine evaluation — WebView2

### 3.1 Capabilities that map to UNTRACE requirements (documented APIs)

| Need | WebView2 mechanism |
|---|---|
| Request filtering | `WebResourceRequested` + `AddWebResourceRequestedFilterWithRequestSourceKinds` (ICoreWebView2_22): covers main page, iframes **including cross-origin**, dedicated workers, **service workers and shared workers**. Blocking = answering with a host-created response. |
| Navigation policy (HTTPS-only, param cleanup, scheme control) | `NavigationStarting`, frame `NavigationStarting`, `LaunchingExternalUriScheme`, `NewWindowRequested` |
| Tracking protection | `EnvironmentOptions.EnableTrackingPrevention` + `Profile.PreferredTrackingPreventionLevel` (None / Basic / Balanced / Strict). Edge's own tracker lists. |
| Certificate validation | Chromium validates; `ServerCertificateErrorDetected` lets the host enforce "always cancel" and show details. |
| Permissions | `PermissionRequested`, `Profile.SetPermissionState`, `Profile.GetNonDefaultPermissionSettings` (read-back for verified state). |
| Downloads | `DownloadStarting` (cancel, choose path, hide default UI), `DownloadOperation` progress. |
| Session isolation / temporary sessions | Named profiles (`ControllerOptions.ProfileName`) and InPrivate (`ControllerOptions.IsInPrivateModeEnabled`). |
| Cookie & site data | `Profile.CookieManager` (enumerate/delete), `Profile.ClearBrowsingDataAsync(kinds)`; per-origin storage via DevTools protocol `Storage.clearDataForOrigin`. |
| Malicious-site reputation (optional) | `Settings.IsReputationCheckingRequired` (Microsoft Defender SmartScreen). Sends data to Microsoft. |
| Proxy auth for a local proxy | `BasicAuthenticationRequested` also fires for proxy challenges (`Uri` = proxy address). |
| Engine status | `Environment.BrowserVersionString`, `NewBrowserVersionAvailable`. |
| Crash dumps kept local | `EnvironmentOptions.IsCustomCrashReportingEnabled`. |
| Escape hatch | `CallDevToolsProtocolMethod` (Chrome DevTools Protocol) for security state, certificate details, storage. |

### 3.2 Limitations found (with evidence)

- **L1 — Third-party cookies.** No profile or settings API blocks them. `CookieManager` only reads/adds/deletes cookies. The supported-flags page lists `PartitionedCookies` and `ThirdPartyStoragePartitioning`, but no third-party cookie block. Edge's `BlockThirdPartyCookies` is a machine-wide Edge policy, not a WebView2 API, and UNTRACE will not write system policies. Chromium's DevTools protocol has an **experimental** `Network.setCookieControls { enableThirdPartyCookieRestriction }`; whether it works and persists in WebView2 157 is unknown → spike S6.
- **L2 — DNS.** No DoH API and no DoH flag on Microsoft's supported-flags page. A Microsoft engineer stated WebView2 uses the OS DNS client. So page DNS follows Windows' resolver. App-scoped DoH is achievable only by routing traffic through a local proxy that resolves names itself (Chromium does not resolve names for proxied requests).
- **L3 — Flags are unsupported in production.** Microsoft's flags page: *"For production apps, do not use these flags."* `--proxy-server` is listed (affects HTTP/HTTPS only). If UNTRACE relies on it, it must **verify** that traffic actually reaches the proxy, and **fail closed** (refuse to load) rather than silently going direct.
- **L4 — Interception gaps and cost.**
  - The legacy filter only sees the main frame and same-origin iframes; the source-kinds API is required for cross-origin iframes and workers.
  - Worker requests are raised on **every** webview in the environment that has a matching filter, so worker filters must be registered on exactly one view, and the originating tab is not directly known.
  - No evidence that WebSocket handshakes are raised (a 2021 report says they are not). Treat as **not covered**; the network-layer proxy is the backstop.
  - The event is raised on the host's UI thread: every intercepted request costs a cross-process hop. Overhead with a `*` filter must be measured (spike S2).
  - Responses from the network cannot be modified (e.g. stripping `Set-Cookie`) without fetching on the page's behalf — rejected as fragile and security-weakening.
- **L5 — Fingerprinting and identifiability.** No anti-fingerprinting API. Setting a custom user agent can clear User-Agent Client Hints. Third-party code (DuckDuckGo's content-scope-scripts) explicitly filters a "Microsoft Edge WebView2" brand from client hints, suggesting WebView2 is identifiable. The `window.chrome.webview` object may also be visible to pages. To be measured in S1.
- **L6 — Runtime data collection.** Per Microsoft's WebView2 data-privacy page, the runtime follows the Windows diagnostic-data setting; *required* data continues regardless. Apps can control SmartScreen and custom crash reporting. If SmartScreen is left on, apps must tell users it sends their information to Microsoft.
- **L7 — Browser extensions.** Supported (unpacked, per profile, opt-in via `AreBrowserExtensionsEnabled`) but **without UI entry points** (no toolbar, badges or popups). Changing extension files removes the extension from the profile. Password-manager and uBlock Origin popups are therefore unusable.
- **L8 — Engine versioning.** Evergreen updates are delivered by Microsoft. This is a security strength (UNTRACE does not own Chromium patching), but timing and version are outside UNTRACE's control, and enterprise policies may alter runtime behaviour.
- **L9 — Windowing (airspace).** A content view is a child HWND; the HTML UI cannot draw over it. Popovers must not overlap content (or use a separate top-level popup). Visual hosting (`CompositionController`) avoids this but adds a lot of complexity — not planned.
- **L10 — Tauri webviews are unsuitable for untrusted content.** Tauri injects `__TAURI_INTERNALS__` and plugin scripts into every webview and registers its protocols there. CVE-2026-42184 (remote origins misclassified as local on Windows, affected Tauri 2.x up to at least 2.10.2; sources disagree whether 2.10.3 or 2.11.1 is the first fixed release) shows the risk class. UNTRACE never loads remote content in a Tauri webview, and pins Tauri ≥ 2.11.1.

### 3.3 Alternatives considered

| Option | Strengths | Weaknesses | Verdict |
|---|---|---|---|
| **WebView2 Evergreen** | Microsoft ships engine security fixes; small footprint; rich documented API; already on every Windows 11 machine | L1–L10 | **Recommended** |
| WebView2 Fixed Version | Version control | UNTRACE would own shipping every Chromium security fix | Rejected |
| CEF (Chromium Embedded Framework) | Full Chromium prefs (cookies, DoH), full interception | UNTRACE owns Chromium patching (security fixes every 1–4 weeks), 150–250 MB, heavy C++ build | Rejected unless gates fail and Electron is unsuitable |
| Electron | Built-in DoH configuration, comprehensive request interception, partitions; well-trodden | UNTRACE owns the Chromium update cadence; Node main process (abandons Rust core); large | **Fallback #1** if M0 gates fail |
| Gecko / WebKit / Servo embedding on Windows | — | No maintained, production-ready Windows embedding | Rejected |
| Custom engine or browser fork | — | Explicitly out of scope | Rejected |

The decisive factor is **who patches the engine**. For a small, security-first project, an engine that Microsoft patches automatically is worth the API limitations, as long as they are stated plainly.

---

## 4. Content filtering integration

| Option | Assessment |
|---|---|
| **A. `adblock-rust` (Brave), native in the Rust core** | MPL-2.0, v0.13.6 (2026-11-17), the engine behind Brave Shields. Supports network filters, hosts syntax, uBlock Origin extensions (`$removeparam`, `$csp`, `$redirect`, `$redirect-rule`, `$method`), cosmetic filters including procedural ones, and scriptlets with **permission masks** (trusted scriptlets). Resources (scriptlets, redirect files) are supplied by the embedder, in uBlock Origin's format. Serializable engine for fast startup. The engine is immutable after build: rebuild in the background, then swap. Default `single-thread` feature makes it `!Send`; it lives on the UI thread where `WebResourceRequested` fires. **Recommended primary engine.** |
| B. uBlock Origin Lite as a WebView2 extension | Correct injection timing, isolated worlds, broad request coverage via declarativeNetRequest. But: no popup/UI in WebView2, its configuration cannot be driven or read back from UNTRACE Settings, list updates are tied to extension releases, GPL-3.0. **Not primary**; useful as a comparison baseline in spike S2. |
| C. Edge tracking prevention | Native, free, but list-based, opaque, no per-site exceptions, no ad blocking. **Complementary layer.** |
| D. Loopback-proxy domain blocking | Covers every connection type (WebSockets, workers, the runtime's own traffic) but sees only host names and has no tab/site context. **Network backstop** for malicious domains. |
| E. System DNS / hosts-file blocking | Modifies Windows system-wide. **Rejected** (violates scope). |

**Recommended composition:** A (URL-level, site-aware) + C (native tracker storage blocking) + D (network backstop, conditional on S3).

**Cosmetic filtering is the riskiest unknown.** Page CSPs can block a main-world script's data fetch (`connect-src`) and inline `<style>` (`style-src`). Three candidate vehicles are compared in spike S4: (a) main-world bootstrap + intercepted data endpoint, (b) host-driven DevTools-protocol stylesheets per frame, (c) a minimal UNTRACE-owned MV3 extension (isolated world, CSP-exempt CSS) — at the cost of enabling extensions in the content environment.

**Candidate lists** (licences to be confirmed before bundling): EasyList and EasyPrivacy (reportedly dual GPL-3.0 / CC BY-SA 3.0), uBlock filters (GPL-3.0), a URLhaus-derived malicious-domain list (abuse.ch data; packaging licence to verify). Keep the default set small.

---

## 5. Feasibility matrix

Status: **Native** = documented engine API · **Owned** = implemented by UNTRACE on documented APIs · **Partial** = only part of the goal is achievable · **Conditional** = depends on a spike or an unsupported mechanism.

| Area | Feature | Mechanism | Status | Key limitation |
|---|---|---|---|---|
| Filtering | Ad blocking | adblock-rust + `WebResourceRequested` (all source kinds) | Owned | WebSockets not seen by this layer |
| | Tracker blocking | EasyPrivacy via same engine + Edge tracking prevention | Native + Owned | — |
| | Malicious-domain filtering | Engine at navigation (interstitial) + proxy backstop; optional SmartScreen | Owned / Conditional | Local lists lag fresh phishing domains |
| | Cosmetic filtering | adblock-rust cosmetic + injection vehicle | Conditional (S4) | CSP interaction; timing |
| | Maintained lists | Bundled baseline + validated HTTPS updates | Owned | No upstream signatures; TLS only |
| | Site exceptions | Exception set consulted before matching | Owned | Edge tracking prevention has no per-site exception API |
| Privacy | DNS visibility | Read-only Windows APIs (adapters, servers, DoH flags) | Owned | — |
| | Encrypted DNS | Loopback proxy + DoH resolver | Conditional (S3, L3) | Relies on a flag Microsoft calls unsupported |
| | Tracking protection | Edge tracking prevention levels | Native | Opaque list, environment-wide on/off |
| | Fingerprinting reduction | Lists + tracking prevention + few low-risk measures | Partial | No engine API; scripts don't reach workers; WebView2 identifiable |
| | Tracking-parameter cleanup | `NavigationStarting` + `$removeparam` | Owned (navigations) / Partial (sub-resources) | Sub-resource URLs cannot be rewritten |
| | Third-party cookie restriction | Tracking prevention + lists + cleanup; experimental CDP | Partial / Conditional (S6) | No supported block API |
| | Privacy transparency | Per-tab counters, data inventory, connection view | Owned | — |
| Security | HTTPS protection | HTTPS-only in navigation policy; Chromium mixed-content blocking | Owned + Native | — |
| | Certificate validation | Chromium + `ServerCertificateErrorDetected` (no bypass) | Native | No API for valid-cert details → DevTools protocol |
| | Permissions | `PermissionRequested` + profile permission APIs | Native | — |
| | Download safety | `DownloadStarting`; Mark-of-the-Web (to verify); optional SmartScreen | Native / Conditional (S5) | — |
| | Session isolation | Profiles + InPrivate | Native | Profile granularity, not per-site containers |
| | Temporary sessions | InPrivate profiles | Native | Disk residue to verify (S5) |
| | Cookie & site data | CookieManager, ClearBrowsingData, CDP storage | Native | — |
| Diagnostics | All listed | Engine/API read-back, self-tests, read-only system queries, local audit log | Owned | — |

---

## 6. Fallback plan if gates fail

| Gate fails | Fallback |
|---|---|
| S1 (Tauri + raw content views don't compose) | Drop Tauri: plain Rust Win32 shell (`windows` crate) hosting a UI WebView2 + content WebView2s, with a hand-written, typed host-object bridge for the UI only. Loses Tauri bundler/updater — replaced by WiX/NSIS + a small signed-update module. |
| S2 (interception coverage or overhead unacceptable) | Shift weight to Edge tracking prevention (Strict) + proxy domain blocking; reduce URL-level filtering to navigations and main resources. Re-evaluate Electron. |
| S3 (proxy flag ignored or unreliable) | Encrypted DNS becomes **diagnostics + guidance only** (show Windows DoH status, explain how the user can enable it in Windows Settings). No system changes. |
| S4 (no robust cosmetic vehicle) | Ship without cosmetic filtering; say so in Settings. |
| S5 (InPrivate leaves residue) | Temporary sessions use a throwaway named profile in a temporary folder, deleted on close, with residue checks in Diagnostics. |
| S6 (no CDP cookie control) | Third-party cookie setting = "Restrict known trackers" only, labelled as such. |
| Several gates fail | Re-open D-001 (engine): Electron is the documented next candidate. |

---

## 7. Unknowns → Milestone 0 spikes

| Spike | Question | Pass criterion |
|---|---|---|
| S1 Shell & composition | Can a Tauri window host raw WebView2 content controllers (z-order, resize, DPI, focus, accelerators) in a separate environment, with no Tauri globals in content? | All interaction checks pass; `__TAURI_INTERNALS__` and `chrome.webview.postMessage` absent in content; memory cost recorded |
| S2 Interception | Which request types reach `WebResourceRequested` on runtime 157, and what does `*` interception + matching cost? | Coverage table produced; p95 page-load overhead ≤ 10 % on a 50-site corpus |
| S3 Loopback proxy & DoH | Is `--proxy-server` honoured for all page traffic, with proxy auth, fail-closed behaviour and no DNS leak? | 0 page-originated system DNS lookups; proxy-down = load fails (no direct fallback) |
| S4 Cosmetic vehicle | Which of three injection vehicles survives strict CSPs, cross-origin iframes and timing? | Hiding works on CSP-strict test pages and cross-origin frames without visible flash on ≥ 90 % of corpus |
| S5 Session & storage | InPrivate residue, profile isolation, history clearing, Mark-of-the-Web on downloads, local crash dumps | No residue after temp session; MOTW present; dumps stay local |
| S6 Third-party cookies | Does `Network.setCookieControls` work and persist across navigations, frames and new views? | 3P cookie test page shows cookie blocked in all frame types |

---

## 8. Sources

- [WebView2 browser flags](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/webview-features-flags)
- [ICoreWebView2_22 — request source kinds](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/win32/icorewebview2_22)
- [Custom management of network requests (WebResourceRequested)](https://learn.microsoft.com/en-us/microsoft-edge/webview2/how-to/webresourcerequested)
- [WebView2 WebSocket events forum report (2021)](https://techcommunity.microsoft.com/discussions/edgeinsiderdiscussions/webview2-websockets-events/2108109)
- [WebView2 browser extensions spec](https://github.com/MicrosoftEdge/WebView2Feedback/blob/main/specs/Extensions.md) · [ICoreWebView2Profile7](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/win32/icorewebview2profile7)
- [PreferredTrackingPreventionLevel](https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.core.corewebview2profile.preferredtrackingpreventionlevel) · [EnableTrackingPrevention](https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.core.corewebview2environmentoptions.enabletrackingprevention)
- [Data and privacy in WebView2](https://learn.microsoft.com/microsoft-edge/webview2/concepts/data-privacy)
- [IsReputationCheckingRequired (SmartScreen)](https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.core.corewebview2settings.isreputationcheckingrequired)
- [BasicAuthenticationRequested (incl. proxy auth)](https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.core.corewebview2.basicauthenticationrequested)
- [WebView2Feedback discussion on secure DNS defaults](https://github.com/MicrosoftEdge/WebView2Feedback/discussions/3990) · [Edge DnsOverHttpsMode policy](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/dnsoverhttpsmode)
- [CoreWebView2Settings.UserAgent (clears UA client hints)](https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.core.corewebview2settings.useragent) · [DuckDuckGo content-scope-scripts PR #2028](https://github.com/duckduckgo/content-scope-scripts/pull/2028)
- [Tauri JS webview reference (unstable multi-webview)](https://tauri.app/reference/javascript/api/namespacewebview/) · [tauri 2.11.0 webview plugin source](https://docs.rs/crate/tauri/2.11.0/source/src/webview/plugin.rs)
- [CVE-2026-42184 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2026-42184)
- [brave/adblock-rust](https://github.com/brave/adblock-rust) · [adblock crate docs](https://docs.rs/adblock/latest/adblock/)
- [CDP Network.setCookieControls (cdproto)](https://pkg.go.dev/github.com/chromedp/cdproto/network)
