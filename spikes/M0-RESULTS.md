# UNTRACE — Milestone 0 Results (Feasibility Spikes)

Date: 2026-11-21 · Machine: Windows 11 build 26300 x64, WebView2 Runtime **157.0.4341.60**, Rust 1.94.1, Tauri **2.12.7**, webview2-com 0.39.1, adblock 0.13.6.

All spikes ran locally against loopback fixture servers. Real-looking host names (`*.test`, and a few known tracker domains for S6) were resolved by the spike proxy to local fixtures, so **no page traffic left the machine**. The only external requests were: downloading EasyList/EasyPrivacy (S2 test data), and a few DoH queries for `example.com` to Quad9 (S3).

Raw results: `spikes/results/*.json`. Code: `spikes/harness` (S2–S6), `spikes/s1-tauri` (S1). Throwaway — not product code.

## Verdict summary

| Spike | Gate | Verdict | Decision impact |
|---|---|---|---|
| S1 Shell & composition | Interactions work, no host globals in content | **PASS** — only with a container child window | D-002 accepted (with container); D-003 two environments, revisit at M1 |
| S2 Interception | Coverage table; overhead ≤ 10 % p95 | **PASS** coverage · **PARTIAL** performance (loopback upper bound only) | D-004, D-005 accepted; real-site corpus still pending |
| S3 Proxy & DNS | No leak; fails closed | **PASS** (flag still unsupported in production) | D-006 accepted; native Windows DoH, no resolver crate |
| S4 Cosmetic vehicle | Strict CSP + cross-origin frames + no flash | **PASS** — embedded-data main-world script | D-015 = vehicle a3; D-022 stays (no extensions) |
| S5 Sessions & storage | No residue; MOTW; local dumps | **PASS** | D-014 confirmed |
| S6 Third-party cookies | Block in all frames and views | **FAIL** (expected fallback path) | D-010: no "block all" setting; tracking prevention Strict verified |

---

## S1 — Tauri shell + raw WebView2 content view

**Setup.** Tauri 2.12.7 window with its own (UI) webview. The content view is a WebView2 controller created through `webview2-com` in a **separate environment** (own user-data folder), loading a local page via virtual host mapping. A driver checked the results by capturing the window (PrintWindow) and sampling pixels: UI bar `#202020`, content `#00a000`, UI showing through = magenta.

**Results.**

| Check | Result |
|---|---|
| Content parented directly to the Tauri window | **Content hidden.** Tauri's `WRY_WEBVIEW` child is above it in z-order (magenta visible). |
| Content parented to an UNTRACE container child window (`WS_CHILD \| WS_CLIPSIBLINGS`, `HWND_TOP`) | **Visible**, UI bar intact, correct after resize (bounds 0,0,884,533). |
| Ctrl+L / Ctrl+T while content focused | Received via `AcceleratorKeyPressed` (key down + up, Ctrl state correct). |
| Tauri globals in content | `__TAURI_INTERNALS__`, `__TAURI__`, `window.ipc` all **undefined**. |
| `chrome.webview` in content | **Present** (`postMessage` and `hostObjects` are functions) **even with `IsWebMessageEnabled=false` and `AreHostObjectsAllowed=false`.** The bridge is inert, but its presence is detectable. |
| User-Agent Client Hints | Brands include **"Microsoft Edge WebView2" 157** (full version 157.0.4341.60) next to "Microsoft Edge" and "Chromium". The UA string itself is identical to Edge's. |
| Memory (private / working set) | UI environment: 6 processes, **144 MB / 304 MB**. Content environment: 6 processes, **136 MB / 304 MB**. Its renderer accounts for about 21 MB private, so the second environment's overhead is about **115 MB private**. |

**Not automatable here (manual at M1):** DPI change across monitors, IME input, mouse-driven focus hand-off between the UI and content views.

## S2 — Request interception

**Coverage** (server log vs. `WebResourceRequested` events, 30 request types):

| Request | Legacy `AddWebResourceRequestedFilter` | `…WithRequestSourceKinds(ALL)` |
|---|---|---|
| Main page, same-origin iframe, scripts, CSS, `@import`, fonts, images, favicon, prefetch, fetch, XHR, beacon, EventSource, dedicated worker + its fetch/importScripts, shared-worker script | Seen | Seen |
| Cross-origin iframe document | Seen | Seen |
| **Cross-origin iframe sub-resources** (image, fetch) | **Missed** | Seen |
| **Shared-worker fetch** | **Missed** | Seen (`shared_worker`) |
| **Service-worker script, install/message fetches, fetch handled through the SW** | **Missed** | Seen (`service_worker`) |
| **WebSocket handshake** | **Missed** | **Missed** |

The source-kinds API is mandatory. **WebSockets are never raised**, so the network layer (proxy) is the only place they can be seen or blocked.

**adblock-rust with EasyList + EasyPrivacy** (136,500 lines):
- Build 96 ms; serialized engine 6.1 MB; deserialize 1.7 ms.
- Matching: mean 4.6 µs (50k synthetic requests). Inside the event handler: p50 7 µs, p99 42 µs. Well under the 0.2 ms budget.
- Known trackers blocked (google-analytics, doubleclick, facebook pixel); first-party and jsDelivr allowed.
- EasyList/EasyPrivacy contain **no `$removeparam` rules for `utm_*`/`gclid`**, so parameter cleanup needs UNTRACE's own small rule set.

**Overhead** (loopback page: 220 resources, 12 runs each, median load-event time):

| Mode | Load event (median) |
|---|---|
| No interception | 211 ms |
| Intercept everything, no-op handler | 250 ms (+38 ms ≈ **0.17 ms per request**) |
| Intercept + adblock matching | 254 ms (+4.3 ms for matching) |

On loopback that is +20 %. The cost is per request, a cross-process event hop on the UI thread, so for the same 220 requests on a real 1.5–3 s page load it would be roughly 1.5–3 %. **Real-site measurement (50-site corpus) is still pending.** It means visiting real websites, so it needs your go-ahead.

## S3 — Loopback proxy and DNS

Browser args: `--proxy-server=http://127.0.0.1:<port> --proxy-bypass-list=<-loopback>`; proxy requires per-launch Basic credentials.

| Check | Result |
|---|---|
| Plain HTTP page, HTTPS sub-resource, WebSocket, loopback fetch, `preconnect` | All went **through the proxy** (WebSocket as `CONNECT`). |
| Proxy authentication | `BasicAuthenticationRequested` fired for the proxy; credentials accepted. **Side effect:** the first navigation reports `NavigationCompleted` failure (status 18, proxy auth required) before the authenticated retry loads the page. The UI must not show that as an error. |
| DNS leak (Chromium net-log) | Proxied names: **no DNS jobs or transactions**, only local request bookkeeping. `dns-prefetch` was suppressed entirely. Control without proxy: full `HOST_RESOLVER_MANAGER_JOB` + `DNS_TRANSACTION`. |
| OS DNS cache as a leak detector | **Not usable.** WebView2 uses Chromium's built-in DNS client, which bypasses the Windows cache. |
| Default DNS behaviour without proxy | Chromium built-in resolver, `secure_dns_mode = Automatic`, queries sent **unencrypted** on this machine. It also performs **WPAD** proxy auto-discovery lookups. |
| Fail closed | Proxy stopped → both a loopback URL and a named URL **failed**; the fixture received **nothing** directly. |
| Runtime background traffic | `config.edge.skype.com` (Edge configuration/experimentation service), always. `nav-edge.smartscreen.microsoft.com`, only while SmartScreen is on; `IsReputationCheckingRequired=false` removed it. Neither can answer the proxy's auth challenge, so **with the authenticated proxy, runtime background traffic is blocked**, including SmartScreen if the user enables it. |
| Windows native DoH (`DnsQueryEx` + `DNS_CUSTOM_SERVER`, DoH template) | **Works.** `example.com` resolved in 61 ms (first query). Requires port 0 in the server address and rejects `BYPASS_CACHE \| NO_HOSTS_FILE` (error 87). Negative control (wrong DoH path) **fails with 9002** → queries really travel over DoH, with no UDP fallback. |

## S4 — Cosmetic filtering vehicles

Test pages carry a strict CSP (`default-src 'self'`, no inline styles, `connect-src 'self'`, report-uri) and a cross-origin iframe with the same CSP. "early" = state measured by a page script placed directly after the element (before first paint).

| Vehicle | Plain page | Strict-CSP page | Cross-origin frame | Flash |
|---|---|---|---|---|
| a1/a2 main-world script + sync XHR to local endpoint | Hidden | **Fails** (connect-src; 2 CSP reports) | Hidden (plain) | None |
| **a3 main-world script, CSS embedded, `adoptedStyleSheets`** | **Hidden** | **Hidden, 0 CSP reports** | **Hidden** | **None** |
| a4 like a3, registered per navigation | Top **missed** (race), frame hidden | Hidden | Hidden | — |
| b1 DevTools isolated world | Fails | Fails | Fails | — |
| c1 extension, static manifest CSS | Hidden | Hidden | Hidden | None |
| c2 extension, `scripting.insertCSS` with fetched CSS | Hidden | Hidden | Hidden | **Flash** (applied after first paint) |

**Chosen: a3.** The data must be embedded in the registered script and selected by `location.hostname`. EasyList + EasyPrivacy cosmetic volume: 13,638 generic rules (~189 KB of selectors) and 10,567 site-specific rules (~484 KB). Parse and memory cost per frame becomes an explicit M6 budget. Scriptlets (34 rules in these lists) are deferred as planned.

## S5 — Sessions and storage

| Check | Result |
|---|---|
| Positive control (persistent profile): marker found on disk in | `History`, IndexedDB, Local Storage, CacheStorage. **Not in `Cookies`**, so cookie values are encrypted at rest (2 cookies were present). |
| **InPrivate profile after close** | **No marker anywhere on disk.** Only an empty-ish `WV2Profile_<name>` folder remains, so temporary profile names must be random. |
| Profile isolation | Other InPrivate and persistent profiles saw **0** cookies. |
| `ClearBrowsingData(BROWSING_HISTORY)` | Marker **removed from `History`** on disk; other storage untouched (as expected). WebView2 does keep history, so UNTRACE must clear it. |
| Downloads | `DownloadStarting` raised (suggested path = user's Downloads folder), path override + `Handled` worked. **Mark-of-the-Web applied:** `ZoneId=3` + `HostUrl`. |
| Custom crash reporting | Dumps go to `<user-data>\EBWebView\Crashpad\reports`. A renderer crash (`Page.crash`) produced a local dump. |

## S6 — Third-party cookies and tracking prevention

Ground truth = `Cookie` header received by the tracker fixture on site B after the user visited site A.

| Scenario | 3P cookies sent cross-site? |
|---|---|
| Baseline (tracking prevention Balanced, unlisted tracker) | **Yes**: header, pixel and JS cookies all sent |
| `Network.setCookieControls{enableThirdPartyCookieRestriction:true}` — same view | No (headers clean) |
| — same view, but cookies already in the jar from another view | Requests clean, **but JS in the cross-origin iframe could still read them** (`document.cookie`): the control does not reach out-of-process iframes |
| — second view, same profile, no CDP call | **Yes**: the control is per view (DevTools target), not per profile |

**Edge tracking prevention** against 6 known tracker hosts (scorecardresearch, quantserve, adnxs, criteo, taboola, hotjar), mapped locally over plain HTTP, with a neutral third-party host as control:

| Level | Read-back | Tracker hosts reached | Neutral 3P loaded |
|---|---|---|---|
| None | 0 | 6/6 | yes |
| Basic | 1 | 6/6 | yes |
| Balanced | 2 | 6/6 | yes |
| **Strict** | 3 | **0/6** | **yes** |

Tracking prevention works in WebView2 with the runtime's built-in lists (no list download was possible during the test), and the level is verifiable by read-back. Balanced restricts storage rather than loads, per Microsoft's docs; storage behaviour was not measured.

The DevTools route is experimental, per view, and misses JavaScript cookie access in cross-origin frames. **No "block all third-party cookies" setting in v1.**

---

## Pending (not blocking M1)

1. **Real-site overhead**: 50-site corpus with filtering on/off. Visits real websites, so it needs product-owner approval.
2. **Manual S1 checks**: DPI change between monitors, IME, mouse focus hand-off.
3. **Single-environment experiment (M1)**: create content views from Tauri's own WebView2 environment, with a separate profile. Accept it only if custom crash reporting, tracking prevention and browser arguments can still be controlled. Potential saving is about 115 MB.
4. **Cosmetic data budget (M6)**: per-frame parse/memory cost of the embedded rule data.
