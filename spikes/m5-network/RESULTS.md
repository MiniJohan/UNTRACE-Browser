# M5 — Network layer and DNS: evidence (2026-11-22)

WebView2 Runtime 157.0.4341.60. Everything below ran on this machine against local fixtures, except the DNS-over-HTTPS check, which looked up `example.com` at Quad9, Cloudflare and Mullvad (as S3 did for Quad9).

| File | What |
|---|---|
| `s7-local-network-access.json` | S7: does the engine protect the local network, with and without the proxy? |
| `probe-engine.json` | M5 probe (`spikes/harness`, `m5`): the real `untrace-net` proxy with the real engine |
| — | `cargo run -p untrace-net --example doh --release`: each Strict provider over DoH (output below) |

## S7 — Local Network Access under the loopback proxy

A "device" server on loopback stands in for the local network: public → loopback is checked the same way as public → local. The engine's own view comes from the DevTools protocol (`Network.requestWillBeSentExtraInfo` → `clientSecurityState`).

| Case | Page's address space | Policy the engine applies | Device reached | Permission asked |
|---|---|---|---|---|
| C0 no proxy, page port declared public (`--ip-address-space-overrides`) | Public | `Allow` | yes (IP literal and `localhost`) | no |
| C1 S3 design: proxy, loopback through it | **Loopback** (the proxy's address) | `Allow` | yes, including a public name pointing at it | no |
| C2 proxy declared public, local destinations direct | Public; target Loopback | `Allow` | yes | no |

- **WebView2 has no local-network protection.** Chrome and Edge ask since version 142; WebView2 lets every request through.
- **Through the proxy, every page is "Loopback"**, as the WICG specification describes (§4.2). Should WebView2 ever enforce the protection, proxied pages would escape it. C2's arguments give the right classes and are kept on file for that day.
- Result: D-040. UNTRACE now blocks such requests itself.

## DNS over HTTPS through `DnsQueryEx` (D-024, D-041)

```
Quad9 IPv4                             68.9 ms  ok via Encrypted (dns.quad9.net)
Quad9 IPv6                             39.9 ms  ok via Encrypted (dns.quad9.net)
Cloudflare IPv4                        37.6 ms  ok via Encrypted (cloudflare-dns.com)
Cloudflare IPv6                        35.5 ms  ok via Encrypted (cloudflare-dns.com)
Mullvad IPv4                           38.3 ms  ok via Encrypted (dns.mullvad.net)
Mullvad IPv6                           34.0 ms  ok via Encrypted (dns.mullvad.net)
negative control (wrong path)          53.6 ms  error: Failed("DNS error 9002")
Automatic would use: []   (this machine's DNS server 192.168.1.26 has no known DoH address)
Automatic example.com: Windows resolver, 32.1 ms
```

Every provider answers on IPv4 and IPv6 addresses. A wrong DoH path fails rather than falling back to plain DNS.

## M5 probe — the real network layer with the real engine

Names (`*-<pid>.test`) are answered from the proxy's self-check table and point at a local TLS fixture.

**DNS leak (S3 method, Chromium net-log).** The page used:
- an HTML page, an image, a `fetch`, a WebSocket;
- `<link rel=dns-prefetch>` and `<link rel=preconnect>`;
- a second (InPrivate) profile.

Across the whole log there is **no** `HOST_RESOLVER_MANAGER_JOB`, `DNS_TRANSACTION` or `HOST_RESOLVER_SYSTEM_TASK`, for any name. The engine resolved nothing itself. Page names appear only in `HOST_RESOLVER_MANAGER_REQUEST` bookkeeping, exactly as in S3. The `dns-prefetch` name never appears at all. Every other name reached the proxy with credentials.

Method note: Chromium does not write a net-log to a path containing `..`. The probe must run with `UNTRACE_SPIKE_UDF` set to a clean absolute path, as S3 did.

**Credentials (D-026).**
- A fresh profile's first navigation completes with status 18 (proxy authentication required). The engine then starts a **new** navigation, with its own `NavigationStarting`, which loads the page. This happened in both the standard and an InPrivate profile.
- UNTRACE ignores the status-18 completion. In the standard profile, its start-up check answers the challenge before any page loads.
- The challenge was recognised by the random realm in every case.

**Bypass detection (M5 exit criterion).** UNTRACE's start-up check is a request from the engine to a random check name that only the proxy can see.
- Through the proxy, it arrived.
- From a second engine started without the proxy arguments (the bypass case), it never arrived within 5 s. The check fails, and Encrypted DNS reads back as *not verified*.
- Unit tests in `app/src-tauri/src/network.rs` cover the read-back side: only a passed check verifies; failed, pending or missing reads *not verified*.

**Fail closed.** With the proxy stopped, a named page and a loopback page both fail, and the fixture receives nothing.

**Background traffic (D-025).** `config.edge.skype.com` and `nav-edge.smartscreen.microsoft.com` asked without credentials only, and were refused. SmartScreen was at its default (on) in the probe; UNTRACE turns it off.

### Finding: a cancelled navigation still sends its request

UNTRACE's malware/phishing warning (D-033) and the HTTPS-only upgrade (D-009) cancel the navigation at `NavigationStarting`. The engine reports the navigation as cancelled (status 14), but:

| Case | What reached the server |
|---|---|
| `https://cancelled-…/m5/cancelled`, cancelled at `NavigationStarting` | `GET /m5/cancelled`, the full request |
| `http://plain-…/m5/plain?secret=1`, cancelled (as the HTTPS-only upgrade does) | `GET /m5/plain?secret=1` **over plain HTTP** |
| The same, plus the page's own request answered with 403 in `WebResourceRequested` | nothing (the request event does fire for the cancelled page) |

- **Before M5, the warning did not stop the request.** A listed site still received the request for the page, with its cookies, before the user had decided anything. HTTPS-only sent the first request of every upgraded address unencrypted.
- The M2/M3 self-checks could not see this: their test hosts never resolve.
- The engine also opened 2–3 connections (without a request) to the cancelled host, probably speculative preconnects. The network layer's backstop refuses those for listed hosts: the self-check's proxy counted 4 such refusals for the malware test host before any page asked for it.
- **Fix (M5):** the host remembers each navigation it cancels and answers that request with 403 in `WebResourceRequested`. Self-check 43 navigates to an `http://` address through the network layer and requires that no plain-HTTP request for that host arrives, while the upgraded attempt does.
- **Still open, with encrypted DNS off:** the engine's bare connection attempt (TCP and TLS handshake, no request) to a listed host is not prevented; with it on, the backstop refuses it.

### Finding: WebSockets and the proxy's challenge

The self-check's probe page is served locally, so it had made no request through the proxy before its WebSockets.
- Both WebSockets reached the proxy without credentials, were challenged (`407`), and the engine did not retry.
- After one ordinary request from the same page, both carried credentials. The phishing canary was refused by the backstop, and the control name by the rebinding guard.
- In the probe, where the page itself was loaded through the proxy, the WebSocket was authenticated from the start.

So the engine answers the challenge for requests but not for WebSockets, and keeps the credentials per site. Real pages load over the network first, so their WebSockets work. A page served entirely from cache or a service worker that opens a WebSocket first would fail (D-026 limitation).

## Page-load overhead with the network layer (real sites, 2026-11-23)

Method: same as the M3 paired run (`compat.exe … paired-net 2`, output `paired-net.json`, `paired-net.log`).
- The 53-site corpus, two rounds, fresh profiles per round, the first engine alternating per site.
- Both engines filter with the bundled lists. "Off" has no network layer; "on" sends everything through `untrace-net` in Automatic mode, UNTRACE's default. On this machine that resolves through the Windows DNS client, because the DNS server has no known DoH address.

| | Pairs | Median off → on | p95 off → on |
|---|---|---|---|
| Host-timed | 101 | 862 → 837 ms (−2.9 %) | 2,853 → 2,324 ms (−18.5 %) |
| Page load event | 98 | 1,016 → 968 ms (−4.7 %) | 2,774 → 2,283 ms (−17.7 %) |

- **Budget "≤ 10 % p95": met.** The fair reading is "no measurable overhead", not "faster": the network layer resolves through Windows' DNS cache, which is shared and warm, while the engine's own resolver starts empty in every fresh profile.
- Pages loaded: 101 of 106 pairs with both engines.
  - nytimes.com (403) and reuters.com (401) fail in both conditions, as in M1 and M3.
  - wikipedia.org's "on" load in round 1 took 5,014 ms, so the runner's 5 s limit counted it as failed. It was the very first page of the run. The same first load took 4,664 ms with the network layer **off** in round 2, so it is a cold start, not the proxy.
- Not measured: Strict mode (encrypted lookups to the provider for every new name). The runner supports it (`UNTRACE_COMPAT_DNS=quad9`).

## Self-check (offline, real app)

See TESTING §9, checks 38–44. First run: 44 of 46 passed. The two failures were test-design errors:
- The WebSocket test used the malware canary, which an earlier check had legitimately continued to for the session.
- The rebinding test used an `http://` name from an HTTPS page, which the engine blocks as mixed content before it reaches the proxy.

Both were fixed. The second run (47 checks) then found:
- the WebSocket challenge behaviour above;
- an ordering problem: check 43 left the tab on another site's error panel before check 44.

After those fixes all 47 pass; the final run is recorded in ROADMAP M5.
