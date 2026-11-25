# M3 — Real-site run with filtering on (2026-11-22)

**Setup:** the M1 corpus (`spikes/m1-compat/sites.txt`, 53 front pages) in a content host configured like UNTRACE, with all four bundled lists on (EasyList and EasyPrivacy 2026-11-22 09:45, URLhaus and phishing domains 2026-11-22 00:0x). Fresh profile, one visit per site. Runner: `crates/untrace-webview/examples/compat.rs` (argument `on`). Raw data: `results.json`, `run.log`, per-site comparison with the M1 run in `comparison.json`.

## Outcome

| | M1 (2026-11-21, no lists) | M3 (2026-11-22, lists on) |
|---|---|---|
| Pages loaded without error | 52/53 | 51/53 |
| Load time, median / p95 (51 sites that loaded in both) | 765 / 1,869 ms | 654 / 1,758 ms |
| Requests blocked | — | 323 on 44 sites (median 3 per site, max 34 on duckduckgo.com) |
| Malware/phishing warnings | — | none (expected for these sites) |

**Load time is compared across days and network conditions, not in alternating pairs.** It shows no sign of a slowdown. Blocking removes requests, and measured matching costs 5–7 µs per request (S2: ~0.17 ms per intercepted request for the event hop). The paired run below verifies the TESTING §4 budget.

## Paired overhead run (2026-11-22, afternoon)

Method (`compat.exe … paired 2`, output `paired.json`, `paired.log`): two engines in one process, each with its own fresh profile — one with no lists, one with the four bundled lists on. Each site is loaded once by each engine; which engine goes first alternates per site and per round, because the second load of a site benefits from the operating system's DNS cache (measured: the second load was ~3.7 % faster at the median, whichever engine it was). Two rounds over the 53-site corpus, new profiles per round. Only the engine being measured is visible.

Two timings per load:
- **host-timed**: from UNTRACE's navigate call until the engine reports the navigation complete (as in M1/M3);
- **load event**: the page's own `loadEventEnd` from the Navigation Timing API, measured inside the engine.

Percentiles are nearest-rank over all page loads where both engines loaded the page.

| | Pairs | Median off → on | p95 off → on |
|---|---|---|---|
| Corpus, host-timed | 101 | 684 → 638 ms (−6.7 %) | 2,164 → 2,264 ms (+4.6 %) |
| Corpus, load event | 99 | 800 → 773 ms (−3.4 %) | 1,976 → 1,897 ms (−4.0 %) |
| Corpus + slowest-site repeats, host-timed | 143 | 889 → 918 ms (+3.3 %) | 2,500 → 2,497 ms (−0.1 %) |
| Corpus + slowest-site repeats, load event | 141 | 1,028 → 983 ms (−4.4 %) | 2,405 → 2,392 ms (−0.5 %) |

**Budget "≤ 10 % p95": met.** With ~100 loads, p95 is the 6th–7th slowest load, so one slow load moves it. The runner's own summary over all 102 corpus pairs reported +13.2 % host-timed. That figure includes one invalid pair: the first load of the run (wikipedia.org, "on", 8 ms) was measured before the engine's blank start page had finished, which shifts the percentile rank. It is then set by a single 3.3 s load of vimeo.com. The runner was fixed (it now waits for the start page), and the seven slowest sites were repeated six times each in fresh profiles (`tail.json`, `tail.log`): p95 −0.3 % host-timed, −4.0 % load event.

Per site, over 6 repeats (median host-timed load, off → on): microsoft.com 2,894 → 2,497 ms, youtube.com 2,399 → 2,328, netflix.com 1,936 → 1,888, twitch.tv 1,269 → 1,238, amazon.com 320 → 325, office.com 1,515 → 1,636, **vimeo.com 1,733 → 1,870 (+8 %)**. vimeo.com looked a little slower with filtering: two of its eight filtered loads took 3.2–3.3 s, while its unfiltered loads never exceeded 1.9 s. It blocks four requests to its own analytics host `arclight.vimeo.com` and one on `vimeo.com`. Five more pairs on vimeo.com alone (`vimeo.json`, `vimeo.log`) showed no difference: median 1,882 ms off vs 1,738 ms on, and the slowest load in each condition 2.8 s. Over all 13 pairs the earlier gap is within the site's normal variation; no cause in UNTRACE was found.

Pages loaded: 51 of 53 in both rounds, with both engines; nytimes.com (403) and reuters.com (401) failed with and without lists, as before.

## Failures and differences, each checked

| Site | Finding | Cause | Verified by |
|---|---|---|---|
| nytimes.com | HTTP 403 in both runs | First-visit bot check (M1 finding) | Same status without lists in M1 |
| reuters.com | HTTP 401, no text | First-visit bot check; M1 saw the same challenge with no text (status not recorded then) | Re-run with lists **off**: same 401 |
| outlook.live.com | Less text than M1 (4,785 vs 11,831; 0 in a re-run) | Runner timing: the probe runs 3 s after the first load completes, during a multi-step redirect to microsoft.com | In UNTRACE itself with blocking on: the page is complete after 12 s (header, hero, buttons, cookie banner). Blocked there: Microsoft telemetry (`*.events.data.microsoft.com`, `admin.microsoft.com`) and an analytics beacon (`rum.hlx.page`) |

No site lost content or functionality because of filtering in this run. Sign-in, video playback and checkout flows were not exercised (front pages only, as in M1).

## Most-blocked hosts (by number of sites)

`www.googletagmanager.com` (6 sites), `o22381.ingest.sentry.io` (4, error reporting), `securepubads.g.doubleclick.net` (4), `browser.events.data.microsoft.com` (3), `play.google.com` (3, log endpoints), then first-party analytics endpoints such as `improving.duckduckgo.com` (31 requests on one page), `arclight.vimeo.com`, Datadog RUM intake, `collector.github.com`, `unagi.amazon.com` and `w3-reporting.reddit.com`. Several sites' own analytics paths are blocked on their own domains (`www.airbnb.se`, `www.google.com`, `www.linkedin.com`), by path rules, without breaking the pages in this run. Full per-page host lists are in `results.json` (`blocked.hosts`).

## Not covered

- Repeat visits with a warm cache (every paired load was a first visit in a fresh profile).
- Breakage beyond the front page (sign-in, media, checkout) and visual checks of every page; only the three pages above were inspected.
- WebSocket traffic: never seen by WebView2's request event (S2); filtered only with the network layer (M5).
