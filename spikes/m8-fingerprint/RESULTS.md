# M8 — Fingerprinting and WebRTC: evidence (2026-11-24)

WebView2 Runtime 157.0.4341.60; Google Chrome 158.0.8127.37 (D-048: Microsoft Edge is not installed on this machine). Everything ran against a loopback test server. Chrome ran with a throwaway profile in a temporary folder, started with background networking, component updates and sync off; the folder was deleted afterwards.

| File | What |
|---|---|
| `page/` | The probe: `fp.html` (page, fresh `about:blank` frame, same-origin and cross-site frames, dedicated, shared and service workers), `fp.js` (the collector), `rtc.html` (WebRTC), `dnt.html` (Do Not Track over time) |
| `run1-all.json` | First full run, incl. WebRTC (`spikes/harness m8`) |
| `run2-fingerprint.json` | Second run of the fingerprint cases, with the `about:blank` collector fixed (in run 1 it failed in every browser: strict-mode `eval` keeps `var FP` inside the eval) |
| `run3-dnt.json`, `run4-dnt-no-tracking-prevention.json` | Do Not Track timing and its variants |

Method: `spikes/harness m8 [prefixes]` (`src/m8.rs`). UNTRACE runs use its real content host with its defaults (block lists, network layer, element hiding: `compat visit`), each in a fresh data folder. The server records every request's headers.

What the probe collects in each context:
- **Navigator and client hints:** navigator values, user-agent client hints (low and high entropy).
- **Locale:** Intl settings and time zone.
- **Rendering:** canvas 2D and WebGL hashes, the GPU strings and an audio hash.
- **Installed things:** fonts (70 probed), speech voices, media-device kinds.
- **APIs:** permission states, storage quota, `window.chrome` and `chrome.webview`, and every global and navigator member name.

## What marks WebView2 (bare WebView2 vs Chrome, same machine)

| Signal | Chrome | WebView2 | Where a page sees it |
|---|---|---|---|
| Client-hint brands | Chromium, Google Chrome | Chromium, **Microsoft Edge WebView2**, Microsoft Edge | `Sec-CH-UA` on **every request** (sent by default), `navigator.userAgentData`, in every context |
| `chrome.webview` | absent | present (8 members, incl. `postMessage`, `hostObjects`), even with web messages and host objects off | page and every frame |
| Payment Request API | present | **absent** (`PaymentRequest` and 5 related globals) | page |
| Speech voices | 19 | **4** (local Windows voices only; Edge offers online voices too) | page |
| `DNT: 1` | not sent | **sent** about 2.5 s after the engine starts; `navigator.doNotTrack` turns `"1"` at the same time (see below) | headers and page |

Version and locale differences (Chrome 158 vs Edge 157, the profiles' languages) are not WebView2-specific. The user-agent string itself equals Edge's (S1).

High-entropy values were the same in every browser on this machine:
- the GPU strings (this machine's graphics card);
- the fonts (59 of 70 found), screen, hardware concurrency, device memory and storage quota;
- the audio hash.

These identify the device, not the browser, and no browser here changes them.

## What UNTRACE adds

- **Nothing a page can read.** UNTRACE (two separate sessions) and bare WebView2 gave identical values for every collected key in the page (`run2`, `diffs_top`: bare vs untrace and untrace vs untrace2 are empty). The headers matched too: same `Sec-CH-UA`, `User-Agent` and `Accept-Language`, apart from the engine's own Do Not Track switch-on (below), which appears in plain WebView2 too.
- **No consistency break.** Where contexts disagree in UNTRACE, they disagree the same way in Chrome. Workers have no `window.chrome`, no `vendor` and no `webdriver` in any browser (12 such places in every run).
- **The fingerprint is stable between sessions**, as in Chrome and Edge: nothing is randomised (D-049 left "farbling" out).

## Candidate measures (D-049: adopted only if consistent everywhere and with low breakage)

| Measure | Result | Adopted |
|---|---|---|
| Remove the WebView2 brand with `Emulation.setUserAgentOverride` (DevTools protocol, user-agent metadata without the brand) | Removed in the page, same-origin frames and dedicated workers. **Not** in the cross-site frame, the shared worker or the service worker, and `Sec-CH-UA` still carried the brand on some requests: a mix a page can detect | no |
| The same with `msWebView2SetUserAgentOverrideOn{Iframes,Workers,ServiceWorker}` | No change | no |
| Remove the brand with a document-start script (patch `NavigatorUAData`) | Inconsistent in every worker; the headers keep the brand | no |
| `Settings.UserAgent` set to the engine's own string (± `msWebView2RetainUserAgentMetadataOnSetUserAgent`) | The brand stays; the shared and service workers then report a different `uaFullVersion` (a new mismatch) | no |
| Hide `chrome.webview` (document-start `delete`) | Consistent: gone in the page and every frame, including a fresh `about:blank` frame read synchronously. Workers never have it | **no: no benefit.** The brand already tells every site "WebView2" in the `Sec-CH-UA` header of every request, and it cannot be removed consistently. Hiding the object removes no information |

No engine switch hides the brand or `chrome.webview`: the runtime's `msWebView2*` feature list (35 names) has none.

**D-011 outcome:** no script-level or protocol-level measure passes D-049. UNTRACE users are recognisable as WebView2 users; among WebView2 users, UNTRACE adds nothing measurable.

## Do Not Track: the engine switches it on by itself

`dnt.html` fetched every 500 ms for 25 s in a fresh plain WebView2:
- The first 5 requests carried no `DNT`.
- From about 2.5 s on (2,538–3,153 ms in 8 runs), every request carried `DNT: 1`, and `navigator.doNotTrack` changed from `null` to `"1"`.
- The profile's `enable_do_not_track` preference read `true` afterwards.

Same result with each of:
- the network layer refusing the engine's own connection to `config.edge.skype.com` (Microsoft's configuration service): 0 connections, 2 refused;
- `--disable-field-trial-config`;
- `enable_do_not_track: false` preset in the profile, which the engine overwrote;
- tracking prevention off.

In the fingerprint runs the switch-on appeared in 12 of 18 WebView2 runs, and in all 4 UNTRACE runs; why some runs never switch on is not known. UNTRACE cannot set it consistently: removing the header would contradict `navigator.doNotTrack`. It is recorded as one more WebView2 trait (THREAT_MODEL).

## WebRTC goes around the network layer (high severity, fixed: D-052)

`rtc.html` gathers ICE candidates with two STUN servers:
- a UDP listener on this computer's LAN address (192.168.1.185), counting what arrives;
- a name under `.invalid`, looked for in the engine's net-log.

Then it opens a data channel between two peers in the same page.

| Engine | Datagrams at the LAN listener | STUN name looked up by the engine itself | Direct data channel |
|---|---|---|---|
| Plain WebView2 | 5 (STUN binding requests) | yes (`DNS_TRANSACTION`) | opens |
| With UNTRACE's network-layer arguments (proxy) | **5** | **yes** | opens |
| UNTRACE's content host as shipped before M8 | **5** | — (no net-log) | opens |
| Proxy + `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` | 5 | yes | opens (the runtime has no such switch) |
| Proxy + profile preference `webrtc.ip_handling_policy = disable_non_proxied_udp` | **0** | **no** | does not open |
| The same in a temporary (InPrivate) profile, preference preset in its folder | **0** | **no** | does not open |

- **Before M8:** any page could make the engine send UDP to devices on the local network and look names up with plain DNS, even with Strict encrypted DNS. That bypassed encrypted DNS, the malware/phishing backstop and local-network protection.
- **Host candidates** were mDNS names (`.local`), so local addresses were not disclosed to the page itself.
- **Fix (D-052):** "Keep WebRTC inside the network layer" (Settings › Network, on). It writes the preference into the standard profile before the engine starts, and into each temporary profile before the engine creates it. Self-check 54 tests it end to end in a normal and a temporary tab.
- **Cost:** WebRTC then connects only through the proxy (TURN over TCP/TLS). Direct peer-to-peer connections fail.
