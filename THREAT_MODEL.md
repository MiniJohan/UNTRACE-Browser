# UNTRACE — Threat Model

Status: **Proposed** · Method: asset/adversary analysis + STRIDE per trust boundary · Review: at every milestone exit and whenever a boundary changes. Last full review: **M8, 2026-11-24** (every row checked against what is built; changes listed in ROADMAP M8).

---

## 1. What UNTRACE protects against — and what it does not

**In scope (UNTRACE aims to reduce):**
- Cross-site tracking by advertisers, analytics and data brokers.
- Exposure to known malicious, phishing and malware-distribution domains.
- Downgrade to unencrypted HTTP and acceptance of invalid certificates.
- Plain-text DNS exposure to the local network/ISP (when encrypted DNS is enabled).
- Unwanted access to camera, microphone, location, notifications and other permissions.
- Data left behind after temporary sessions.
- Untrusted web content gaining access to UNTRACE's privileged code or settings.
- Tampered filter lists or app updates.

**Out of scope (UNTRACE does not claim):**
- Anonymity or IP-address hiding (UNTRACE is not Tor and not a VPN).
- Resistance to a global or state-level network adversary, traffic analysis, or TLS SNI observation.
- Protection once local malware runs as the user or as admin (it can read any user file and inject into any process).
- Protection against Chromium zero-days beyond Microsoft's Evergreen patching and Chromium's sandbox.
- Complete fingerprinting resistance (see D-011).
- Control over Microsoft's required runtime diagnostic data (see D-013).
- Protection of other browsers or system-wide traffic.

---

## 2. Assets

| ID | Asset | Sensitivity |
|---|---|---|
| A1 | Browsing activity (URLs, sites, timing) | High |
| A2 | Cookies, session tokens, site storage | High (account takeover) |
| A3 | Downloads and files saved by the user | High (malware delivery) |
| A4 | Site exceptions and permission decisions | Medium (reveal visited sites) |
| A5 | UNTRACE settings and protection state | Medium (silent downgrade = harm) |
| A11 | Bookmarks (D-055) | Medium (reveal sites the user chose) |
| A6 | Filter lists, scriptlet resources, compiled engine | Medium (integrity: run in every page) |
| A7 | App update channel | Critical (code execution) |
| A8 | DNS queries | High |
| A9 | Crash dumps | High (may contain page memory) |
| A10 | Host system integrity (Windows settings, other apps) | High |

## 3. Adversaries

| ID | Adversary | Capability | Goal |
|---|---|---|---|
| T1 | Trackers / ad networks | Third-party scripts, pixels, iframes, redirects, link decoration, bounce tracking, fingerprinting | Cross-site profiles |
| T2 | Malicious website | Arbitrary HTML/JS in a sandboxed renderer, pop-ups, downloads, permission prompts, external-protocol launches, crafted URLs/titles/filenames | Phishing, malware, escape to host |
| T3 | Network observer (public Wi-Fi, ISP) | Observe/modify plain traffic and DNS | Profiling, injection, downgrade |
| T4 | Supply-chain attacker | Compromise a list maintainer, release host, CI, or dependency | Code or rule injection at scale |
| T5 | Other local unprivileged process | Connect to loopback ports, read world-readable files | Abuse the proxy, read data |
| T6 | Someone with later access to the disk (shared PC, lost laptop, forensics) | Read the user profile | Recover browsing data |
| T7 | Runtime vendor data collection | Telemetry within the WebView2 runtime | Diagnostics (not malicious, but outside user control) |

---

## 4. Trust boundaries

```
                         ┌──────────────────────── UNTRACE process ─────────────────────────┐
   Internet ── B6 ──►    │  B3: UI view ⇄ Rust core (Tauri IPC, capability-scoped)          │
   (lists, updates,      │  B2: WebView2 events ⇄ Rust core (all event data untrusted)      │
    DoH)                 │  B5: loopback proxy ⇄ local processes                            │
                         └──────────────┬───────────────────────────────────▲───────────────┘
                                        │ COM                               │ CONNECT + auth
                         ┌──────────────▼───────────────────────────────────┴───────────────┐
                         │  WebView2 browser process (Microsoft)                            │
                         │  B1: renderer sandbox ── untrusted web content (per-site procs)  │
                         │  B4: content views have no bridge to UNTRACE                     │
                         └──────────────────────────────────────────────────────────────────┘
   Disk: %LOCALAPPDATA%\UNTRACE ── B7 (per-user ACL; config validated on load)
   Windows system configuration ── B8 (read-only to UNTRACE)
```

| Boundary | Between | Enforced by |
|---|---|---|
| B1 | Web content ↔ WebView2 browser process | Chromium sandbox + site isolation (Microsoft) |
| B2 | WebView2 runtime ↔ UNTRACE core | COM API; UNTRACE validates all event data |
| B3 | UI view ↔ UNTRACE core | Tauri capabilities (UI window only), typed commands, CSP, navigation lock |
| B4 | Content views ↔ UNTRACE | No host objects, no web messages, no Tauri scripts/protocols |
| B5 | Loopback proxy ↔ other local processes | Loopback bind, random port, per-launch proxy credentials |
| B6 | UNTRACE ↔ internet services it calls | TLS, signatures (updates), validation (lists) |
| B7 | UNTRACE data ↔ other users / tampering | NTFS per-user profile ACLs, schema validation, atomic writes |
| B8 | UNTRACE ↔ Windows configuration | Policy: read-only; no admin rights |

---

## 5. Threats and mitigations (STRIDE)

Residual risk: **L** low · **M** medium · **H** high (after mitigation).

### B1/B4 — Web content → UNTRACE

| Threat | STRIDE | Mitigation | Residual |
|---|---|---|---|
| Page calls UNTRACE privileged functions | E | Content views have no bridge (D-002). S1 verified that `__TAURI_INTERNALS__`, `__TAURI__` and `window.ipc` are absent. `chrome.webview.postMessage`/`hostObjects` still exist as functions but are disabled (`IsWebMessageEnabled=false`, `AreHostObjectsAllowed=false`); UNTRACE registers no message handler and no host objects | L |
| Page navigates the UI view or frames it | E/T | UI view refuses non-app navigation; `frame-src 'none'`; content cannot address the UI view | L |
| Page abuses a local endpoint of UNTRACE | I | None exists: M6 embeds the hiding data in the scripts (D-015), the self-check's pages exist only in its own instance, and the proxy accepts nothing without this launch's credentials (B5) | L |
| Renderer exploit | E | Chromium sandbox, Microsoft patching; UNTRACE never disables sandbox or site isolation; refuses to run elevated | M (inherent) |
| Public site sends requests to the router, NAS, printer or services on this computer (CSRF, DNS rebinding) | E/T/I | **M5 finding (S7):** WebView2 applies no local-network protection (`localNetworkAccessRequestPolicy: Allow`). D-040: the request layer blocks requests from public pages to loopback/local addresses and local names, unless the user allowed the site; the network layer refuses public names that resolve locally unless announced, and always after they resolved publicly (rebinding). Self-check 41–42 | M: top-level navigations are allowed (as in other browsers); with encrypted DNS off, rebinding is not caught; worker requests are judged by their referrer |
| Page tampers with main-world injected scripts | T | Never place secrets in injected scripts; treat their output as untrusted; prefer isolated-world vehicles (D-015). M6: the hiding script keeps its data in a closure (pages cannot read it), exposes nothing but its adopted stylesheets, and only ever hides; a page can remove the stylesheets (it then shows its own ads) | L |
| Scriptlets run third-party code inside every page they apply to (D-057) | T/E | Only the scriptlets bundled with UNTRACE run (uBlock Origin's, pinned to a release, `resources/ubo-scriptlets.json`); a list chooses which and with what arguments, and cannot bring code. "Trusted" scriptlets, which can put any text into a page, only from uBlock Origin's own lists. They run in the page's own context, with the same power as the page's scripts, not more; the per-site switch turns them off. A compromised uBlock Origin list could still misuse the bundled scriptlets on a site (for example break it, or remove what a page shows) | M: the lists are fetched over HTTPS from uBlock Origin's GitHub Pages and validated, as EasyList is |
| A page's click opens an ad or scam window (pop-under) | T/I | D-057: new windows checked against the lists' pop-up rules (which the matching library drops) and the malware/phishing lists, also when a blank window is sent to an address within 15 s; self-check | L: networks no list knows yet still get through |
| A page sends its own tab to an ad or scam page (click hijack, tab-under) | T/I | D-058: a top-level navigation a page starts is cancelled when the lists block its address as a page (`$document` and host-only rules, as uBlock Origin's strict blocking); the tab stays, a notice names the host; navigations the user starts are never stopped; self-check | L: landing pages no list knows yet still load; the ad scripts that send pages there are blocked by the request rules |
| A list rule the matching library cannot compile disables the rules fused with it | T | D-058: such rules (lookahead and other unsupported regular expressions) are dropped before every engine is built; a built-in canary pair proves it in every engine, cached ones included; self-check | L |
| A damaged or malicious list smuggles CSS through a hiding rule (e.g. `url(…)` requests) | I/T | M6: selectors containing `{`, `}`, `/*` or a leading `@` are refused before use, so no declaration can be written; each rule is its own CSS rule, so an invalid one drops alone; lists are validated as in M3 | L |

### B2 — WebView2 events → core

| Threat | STRIDE | Mitigation | Residual |
|---|---|---|---|
| Crafted URL, title, header or filename confuses parsing / UI spoofing | S/T | Parse with `url` crate; display registrable domain prominently; titles and filenames rendered as text, length-limited; IDN shown as punycode when mixed-script | L |
| Download with deceptive name/extension | S | Show real extension; warn on executable types; ask where to save; Mark-of-the-Web retained (verified in M2 for Internet-zone sources; Windows does not mark intranet/localhost files); optional SmartScreen | M |
| Permission-prompt spam / clickjacking | S/E | Prompts rate-limited per site, shown in UNTRACE UI with origin; default deny for non-listed permissions; no "remember" unless chosen | L |
| External protocol launch (`ms-settings:`, `search-ms:` etc.) | E | Implemented (M2): abused schemes refused outright; others need a user gesture and an explicit prompt each time; hand-offs never replace the current page (self-check 19) | L |
| Pop-up/redirect floods | D | Pop-ups only with user gesture (engine default) and opened as tabs; per-tab navigation rate limit | L |
| Event-handler slowness → UI freeze | D | Handlers bounded (no I/O on UI thread); match budget measured in S2 | L |

### B3 — UI view ↔ core

| Threat | STRIDE | Mitigation | Residual |
|---|---|---|---|
| Compromised npm dependency in the UI | E/T | Minimal dependencies (React only), lockfile, audit; commands are narrow and validated in Rust; no fs/shell plugins | M |
| UI command with malicious arguments | T | Rust-side validation for every command; settings changes go through the protection registry. M8: the validators behind every string argument fuzzed without a finding (TESTING §5) | L |
| Remote content in a Tauri webview | E | Never happens by design (D-002); Tauri ≥ 2.11.1 | L |

### B5 — Loopback proxy

| Threat | STRIDE | Mitigation | Residual |
|---|---|---|---|
| Other local process uses the proxy | E/I | Per-launch random credentials (192-bit password from the system RNG, compared in constant time); loopback bind only; credentials given to the engine only when the challenge carries this launch's random realm. Self-check 39 | L |
| Malformed request crashes proxy | D | Rust, no unsafe code in the parser; 16 KB head, 100 headers, 15 s to send them, 1,024 connections; strict parser tested with 200,000 mutated heads per test run (it found and fixed one acceptance bug: `@[fe80::1]` as a host) and fuzzed coverage-guided in M8, which found that a lone CR or LF inside a header line was forwarded to the server (header smuggling; only this launch's engine could send it, and Chromium does not). Now refused, with regression tests; fail closed | L |
| Proxy silently bypassed (flag ignored, policy override) | T | M5: at every start, a request from the engine to a random check name must reach the proxy with credentials before the first page loads; if not, Encrypted DNS shows *not verified* and Diagnostics fails the check. Per page, the site panel says whether the network layer saw the host. If the proxy cannot start, no page opens | L–M (L3) |
| DNS leak outside DoH | I | S3 and M5 probe: Chromium's net-log shows no resolver jobs for proxied hosts, `dns-prefetch` suppressed; Strict mode has no fallback and resolves nothing without a server; the DoH negative control fails (9002). **M8 finding:** WebRTC STUN/TURN names were still looked up by the engine itself; closed by D-052 (WebRTC only through the network layer, self-check 54) | L–M (WebRTC names leak only with D-052 switched off) |
| Encrypted DNS quietly downgraded in Automatic mode | I | Automatic falls back to the Windows resolver when DoH fails, by design (D-023); every fallback is counted in Diagnostics; Strict never falls back | M (Automatic) · L (Strict) |
| WebSocket opened before the page used the network layer fails (engine does not answer the proxy's challenge for WebSockets) | D (compatibility) | Pages loaded from the network authenticate first; documented in D-026 | L–M: cache- or service-worker-only pages that open a WebSocket first |
| Connection record reveals browsing | I | Hosts contacted are kept in memory only (2,000 max), never logged or written; "Forget records" and the data page clear them | L |
| Runtime background traffic (configuration service, SmartScreen) bypasses user intent | I | S3: these requests cannot authenticate to the proxy and are blocked; every blocked host is listed in Diagnostics; policy decided in D-025. M8 re-measured: `config.edge.skype.com` 0 connections, refused | L (network layer on) · M (off) |
| WPAD proxy auto-discovery on untrusted networks (network layer off) | T/I | S3 observed WPAD lookups without an explicit proxy; enabling the network layer removes them; documented | M |

### B6 — Network services UNTRACE calls

| Threat | STRIDE | Mitigation | Residual |
|---|---|---|---|
| Malicious app update | T/E | M9: Tauri's updater checks the installer's Ed25519 signature before it runs it, and the signature must be for exactly the announced version (`requireSignedVersion`), so a tampered manifest cannot install an older signed release. The key and its password are held offline by the product owner (RELEASING.md). Self-check 56. Authenticode: not yet (D-016) | L (update channel) · M (first download: no Authenticode yet, so SmartScreen warns and the user cannot verify the publisher; SHA256SUMS on the release page) |
| Malicious or broken filter list | T/D | HTTPS (TLS 1.2+, Windows certificate checks) from fixed addresses; validation before use: 16 MB cap, UTF-8, expected list title, minimum rule count, parse-error ratio, no shrinking below a per-list fraction of the previous version (M3, unit-tested); previous copy kept and used when the current one is damaged (checksums); cached engine used only after every list canary matches; no scriptlets or redirect resources until M6 (then only from bundled resources; trusted scriptlets only for trusted lists); CSS `url(`/`image-set(` forbidden by engine | M |
| Compromised DoH provider | I | User chooses provider; Automatic mode adds no new third party | M |
| Vulnerable or compromised Rust dependency | T/E | `Cargo.lock`. Every full check runs cargo-deny (crates.io only, no git sources, allowed licences, RustSec advisories) and cargo-audit (D-051). M8 found and fixed RUSTSEC-2026-0594 (`cookie` 0.18.2, via Tauri, updated to 0.18.3). Six advisory warnings remain, all for Linux-only crates that the Windows build does not include | M (inherent to any dependency) |
| Update/list requests reveal usage | I | No identifiers. Disclosed in the privacy notice and in Settings. The app update check (once a day, GitHub) and the list updates each have their own switch | L |

### B7 — Data at rest

| Threat | STRIDE | Mitigation | Residual |
|---|---|---|---|
| Later disk access reveals history | I | No UNTRACE history. M4: engine history cleared before each session; cache deleted on close by default, cookies and site data optionally; anything a session failed to clear is cleared at the next start before any page loads (D-038). Temporary tabs: InPrivate profile, residue checked by self-check 35. Data page lists what is stored and deletes it per category or per site; the audit log names categories, never sites | M: cookies kept by design (D-014); the engine's per-site engagement scores survive its delete functions until the next start, when UNTRACE removes them (D-039) |
| A navigation UNTRACE cancels (malware/phishing warning, HTTPS-only upgrade) still sends its request | I/T | **M5 finding:** the engine sends a cancelled navigation's request: the listed site received the page request, and HTTPS-only's first request went out unencrypted. Fixed: UNTRACE answers that request itself with 403 in the request event; self-check 43; probe evidence in `spikes/m5-network/RESULTS.md` | L–M: with encrypted DNS off, the engine's bare connection attempt (handshake, no request) to a listed host is not prevented |
| Tracking parameters in links identify the click | I | M4: listed parameters removed from page and frame GET requests before they are sent (D-027); verified against a local fixture, including server redirects and frames | L: unlisted parameters, or IDs hidden in the path |
| A temporary session leaks into the normal profile | I | Separate InPrivate profile with a random name; per-site choices made there stay in memory; pop-ups stay temporary (D-036) | L: downloaded files and crash reports persist |
| Config tampering downgrades protections | T | Schema validation; tampered config → defaults + notice + audit entry; Diagnostics shows effective state from read-back | M (same-user malware out of scope) |
| Crash dumps leak page memory | I | Local only, 7-day deletion, listed in inventory | L |
| An imported bookmarks file (from anywhere) smuggles a script, a local file or an oversized entry into the bookmarks, or crashes the parser | T/E | D-055: the file is only parsed, never rendered; only http and https addresses are kept (`javascript:`, `file:` and engine pages refused); titles one line and bounded; icons from files ignored; limits on size, count and folder depth; the user picks the file. Fuzzed (`bookmarks_file`): HTML and tampered `bookmarks.json`, with the stored invariants and an export → import round trip checked | L |
| Bookmarks reveal sites the user chose | I | Local only, never sent; the activity log records counts, not addresses; "Delete all bookmarks" in the panel | L: they are kept until the user removes them, also from temporary tabs (the panel says so) |
| A saved security report or exported activity log reveals browsing | I | M7 (D-047): the report holds settings, check results, list state, DNS setup and a log summary; it never holds sites visited, host names contacted, cookies, downloads, saved permissions or per-site exceptions (unit test with a planted host name). Every mention of the user's profile folder appears as `%USERPROFILE%` (whole page, plain, JSON- and HTML-escaped; unit test through the full report). Written only where the user chooses in the Windows save dialog; a strict CSP and no scripts, so opening it runs nothing. The activity log never records addresses or sites | L: adapter names, DNS server addresses and the list of switches describe this computer's setup; a profile path written in 8.3 short form would not be masked. The exported activity log is a verbatim copy and keeps local file paths |
| The self-check run from Diagnostics touches the user's profile or network | T/I | M7 (D-046): a separate process with its own data folder (`<data root>\self-check`), offline (its test pages are served from local folders under `.invalid` names, and it runs no list updates), no single-instance lock on the user's instance; it is stopped after 6 minutes | L |

### B8 — System

| Threat | STRIDE | Mitigation | Residual |
|---|---|---|---|
| UNTRACE silently changes system networking | T | Read-only policy; no admin rights; code review rule; test asserts no system writes | L |

### Tracking-specific threats (T1)

| Technique | Mitigation | Residual |
|---|---|---|
| Third-party scripts/pixels | adblock-rust + Edge tracking prevention | L–M |
| Third-party cookies | Tracking prevention (Strict blocks known trackers, verified S6) + lists; no full block — the DevTools route covers one view only and misses JS cookie access in cross-origin frames (S6) | **M–H** (L1, confirmed) |
| Link decoration (`gclid`, `fbclid`, `utm_*`) | Parameter cleanup on navigations | M (sub-resources not covered) |
| Bounce tracking / redirect trackers | Lists; tracking prevention | M |
| CNAME-cloaked trackers | Network layer sees only the hostname; no CNAME inspection unless resolver exposes it (evaluate in S3) | M |
| Fingerprinting | Lists, tracking prevention, minimal changes | **H** (inherent, D-011) |
| WebView2 identifiability | Disclosed. Measured in M8 (D-011): the "Microsoft Edge WebView2" client-hint brand on every request and in every context, `chrome.webview`, no Payment Request API, only local speech voices, and `DNT: 1` (the engine switches it on itself about 2.5 s after start). No removal is consistent (D-049: DevTools override, script and `Settings.UserAgent` tried). UNTRACE's own settings add nothing a page can read (identical to bare WebView2 across sessions) | **H** (inherent, confirmed) |
| WebRTC traffic around the network layer (UDP to local devices, STUN/TURN names looked up with plain DNS, even in Strict mode) | **M8 finding, fixed (D-052):** the engine preference `webrtc.ip_handling_policy = disable_non_proxied_udp` is written into every content profile before the engine loads it, so WebRTC connects only through the network layer. Self-check 54 (normal and temporary tab, a UDP stand-in on the LAN address) | L with the switch on (default). With it off, or encrypted DNS off: WebRTC is not covered, and Settings says so |
| WebSocket-based tracking | Not visible to the request layer (S2). M5: the network layer blocks malware/phishing hosts for WebSockets too (D-042, self-check 40); ad/tracker hosts are not blocked there, because per-site exceptions could not apply | M |

---

## 6. Accepted residual risks (require product-owner acknowledgement)

1. Third-party cookies cannot be fully blocked with supported APIs (L1).
2. Encrypted DNS depends on a browser flag Microsoft calls unsupported in production (L3). M5 verifies the route at every start and fails closed if the proxy cannot start.
7. WebView2 has no local-network protection of its own; UNTRACE's (D-040) does not cover top-level navigations, and covers DNS rebinding only with encrypted DNS on.
3. Fingerprinting resistance is modest; UNTRACE users are identifiable as WebView2 users (L5; measured in M8: brand on every request, `chrome.webview`, no Payment Request API, engine-set Do Not Track). No consistent removal exists (D-011, D-049).
4. Microsoft's required runtime diagnostic data cannot be disabled (L6).
5. Renderer exploits are mitigated only by Chromium's sandbox and Microsoft's patch speed.
6. Filter lists have no upstream signatures; integrity relies on TLS + validation.

## 7. Review triggers

Re-run this model when: a new boundary or component is added (e.g. extension vehicle, network layer), a protection's mechanism changes, a relevant WebView2/Tauri/adblock-rust security advisory appears, or before each release.
