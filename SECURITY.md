# UNTRACE — Security

Status: **Draft (pre-release)**. Security is treated as an ongoing process: this file, THREAT_MODEL.md and the baseline below are reviewed at every milestone exit.

---

## 1. Reporting a vulnerability

Please report vulnerabilities privately through **GitHub's private vulnerability reporting** on UNTRACE's repository, [MiniJohan/UNTRACE-Browser](https://github.com/MiniJohan/UNTRACE-Browser): open its *Security* tab and choose *Report a vulnerability*. Do not open public issues for vulnerabilities.

- **Response times:** we acknowledge reports within 5 working days and give an assessment within 14.
- **Disclosure:** coordinated, by default 90 days after the report or when a fix is released, whichever comes first.
- **Credit:** reporters are credited in the release notes unless they ask not to be.
- **Scope:** UNTRACE's own code, its installer and update channel, and how it configures the WebView2 engine. Vulnerabilities in WebView2 itself go to Microsoft (MSRC); in a bundled block list, to its maintainers.

## 2. Supported versions

Only the latest release receives fixes. The WebView2 engine is updated by Microsoft independently; UNTRACE refuses to start below a minimum engine version.

## 3. Security guarantees (what UNTRACE commits to)

1. Web content cannot call UNTRACE's privileged code — content views have no host bridge.
2. UNTRACE never decrypts traffic and never installs certificates.
3. Invalid certificates are never accepted (no bypass in v1).
4. UNTRACE never changes Windows system-wide settings and never needs admin rights.
5. UNTRACE sends no telemetry. Every outbound request UNTRACE itself makes is listed in Diagnostics.
6. App updates are signature-verified before installation.
7. Every protection reports its verified state; an unverifiable state is shown as such, never as "On".

And what it does **not** commit to: see THREAT_MODEL.md §1 (no anonymity, no IP hiding, limited fingerprinting resistance, no control over Microsoft's required runtime diagnostics).

## 4. Hardening baseline

### 4.1 Process
- Runs as a standard user; refuses to start elevated.
- Single instance; data folders created with the user's default (private) profile ACLs and checked by Diagnostics.

### 4.2 UI view (trusted)
- Loads bundled assets only; navigation lock; strict CSP (ARCHITECTURE §3.2).
- Tauri capabilities: UNTRACE commands, window `main` only, no remote URLs, no `fs`/`shell`/`http` plugins, `withGlobalTauri` off.
- Every IPC command validates input in Rust and has a unit test for invalid input.

### 4.3 Content views (untrusted)
- `AreHostObjectsAllowed = false`, `IsWebMessageEnabled = false`, no Tauri scripts or protocols.
- Password autosave and autofill off; DevTools off by default; remote debugging never enabled.
- No browser flags except `--proxy-server` / bypass list when the network layer is on; Diagnostics flags anything else found in effect (including via policy or environment variable).
- Schemes: `file:`, `edge:`, `chrome:`, `view-source:` blocked. External-application links known to be abused (`ms-msdt`, `search-ms`, `ms-appinstaller`, …) are refused; others are asked about each time, only after a user gesture (D-031).
- The engine's own error pages are off; UNTRACE's panels offer no way past a certificate error (D-008, D-029).
- Permission requests are asked about or refused by policy; downloads are questions first and flag programs (D-031).
- Certificate errors always cancelled.
- Sandbox and site isolation never disabled.

### 4.4 Loopback proxy
- Bound to `127.0.0.1` on a random port, per-launch credentials, bounded buffers and timeouts, fuzzed request parser, fail closed.
- *M5, as built (`crates/untrace-net`):*
  - **Credentials:** a random user name and 192-bit password from the system RNG, compared in constant time. They are given to the engine only when the challenge carries this launch's random realm.
  - **Limits:** 16 KB request head, 100 headers, 15 s to send them, 1,024 open connections.
  - **Traffic:** `CONNECT` tunnels are blind byte copies (D-007). Plain HTTP is forwarded once, without proxy or hop-by-hop headers.
  - **Checks:** malware/phishing hosts are refused (D-042), and so are public names that point into the local network (D-040).
  - **Start-up:** the route is verified at every start; if the proxy cannot start, no page opens.
  - **Parser testing:** the request-head parser is exercised with 200,000 mutated inputs on every test run, and was fuzzed (coverage-guided) in M8. That campaign found that a lone CR or LF inside a header line was forwarded to the server. It is now refused, with regression tests (TESTING §5).

### 4.5 Filter lists and resources
- *M6:* element-hiding selectors are refused if they contain `{`, `}`, `/*` or start with `@` (no declaration can be injected), then parsed by the engine one rule at a time. The page script holds only public list data. No scriptlet or other list-supplied code runs (D-043).
- **Fetching:** HTTPS only, from the fixed addresses in the catalog (D-032), via Windows' WinHTTP with TLS 1.2+, Windows certificate validation, redirects to HTTP refused, and no cookies. Only lists that are switched on are fetched, and only when the list's `Expires` says so. The self-check never fetches.
- **Validation before use (M3, unit-tested):** 16 MB cap, UTF-8 text, the list's own `Title:`, a minimum rule count, at most 10 % (Adblock) or 2 % (host lists) unparseable rules, and no shrinking below a per-list fraction of the previous version. A refused download is recorded with its reason in Diagnostics; the copy in use stays.
- **Storage:** the previous copy is kept. Checksums detect damaged files, which fall back to the previous copy, then to the bundled snapshot. A cached engine is used only after each list's canary rule matches (D-032).
- **No code from lists:** M3 loads network rules only. Scriptlets and redirect resources (M6) will come only from the bundled, pinned resource set; trusted scriptlets only for lists UNTRACE marks as trusted. Lists have no upstream signatures; integrity relies on TLS plus validation (THREAT_MODEL residual risk 6).

### 4.5b Diagnostics output (M7)
- The security report and an exported activity log are written only where the user chooses, through the Windows save dialog. Neither contains addresses, host names contacted, cookies or per-site settings; profile paths appear as `%USERPROFILE%`. The report is static HTML (no scripts, strict CSP).
- The self-check started from Diagnostics is the same program, in its own data folder and offline; it never reads or changes the user's profile.

### 4.6 Updates
- Tauri updater with Ed25519 signatures; private key kept offline, never in CI secrets for unattended signing without review.
- Installer Authenticode-signed (certificate procurement: D-016).
- Release builds reproducible from a tagged commit with committed lockfiles.

### 4.7 Data
- Data inventory and retention per ARCHITECTURE §8, shown in the app (Settings › Your data) with a delete button per category. Audit log never contains URLs or site names; deletions are logged by category only. Crash dumps local, deleted after 7 days at start (M4). Cache deleted on close by default; anything a session could not clear is cleared at the next start before any page loads (D-038). Temporary tabs use InPrivate profiles; self-check 35 verifies no residue on disk. The engine's per-site engagement scores, which none of its delete functions remove, are removed by UNTRACE at every start before the engine runs (D-039).

## 5. Secure development practices

- **Rust:** `#![forbid(unsafe_code)]` in every crate except `untrace-webview` (COM interop) and `untrace-net` (only if needed for Windows APIs); each `unsafe` block carries a `// SAFETY:` comment and is reviewed.
- **Dependencies:** D-020. `cargo deny` (licences, advisories, bans, duplicate versions) and `cargo audit` in CI and in every local full check (D-051; M8 found and fixed RUSTSEC-2026-0594 in `cookie`); `npm audit` for the UI; lockfiles committed; dependency updates reviewed, not auto-merged.
- **Pinned upstreams:** Tauri ≥ 2.11.1 (CVE-2026-42184), adblock pinned minor, webview2-com pinned; advisories for these watched.
- **Review:** every change touching a trust boundary (THREAT_MODEL §4) gets a security note in its PR description and an update to THREAT_MODEL.md if a boundary changes.
- **Testing:** security tests in TESTING.md §5 are release-blocking.
- **Secrets:** no secrets in the repository; update-signing key offline.

## 6. Privacy notice (to be shown in-app)

- UNTRACE itself: no accounts, no telemetry, no cloud. Stored data is listed in Settings › Your data.
- Microsoft Edge WebView2 runtime: as a Windows component it sends required diagnostic data to Microsoft according to Windows' diagnostic-data setting; UNTRACE cannot disable this. Crash dumps are kept local by UNTRACE. Observed on its own (M0, S3): the runtime contacts `config.edge.skype.com` (configuration/experimentation service), and `nav-edge.smartscreen.microsoft.com` while SmartScreen is on. With the network layer on, these background requests are blocked and listed in Diagnostics (D-025). Without the network layer, the runtime also performs WPAD proxy-discovery lookups.
- Microsoft Defender SmartScreen (if enabled by the user): sends information about visited sites and downloads to Microsoft.
- Filter-list updates contact each list's maintainer through Windows' own networking (Windows looks up those two host names, even in Strict mode); app update checks contact the release host. With Encrypted DNS on (Automatic by default), names are looked up by UNTRACE's network layer through Windows' DNS client: encrypted to your DNS server's provider when Windows knows its DNS-over-HTTPS address, otherwise as Windows normally does; in Strict mode always encrypted to the provider you chose (Quad9, Cloudflare, Mullvad or your own), which sees every name you look up. Names and hosts contacted are kept in memory only.
