# M6 — Cosmetic filtering: evidence (2026-11-23)

WebView2 Runtime 157.0.4341.60. Offline: the spike proxy maps every name the test uses to a local TLS fixture.

| File | What |
|---|---|
| `spike-cost.json` | `spikes/harness m6`: cost and correctness of the document-start script, built from the bundled EasyList + EasyPrivacy by `untrace_filter::cosmetic` |

## The rules (bundled EasyList + EasyPrivacy)

| Kind | Count | Applied |
|---|---|---|
| Generic (every site) | 13,638 | yes; 13,205 of them keyed by a class or id, so only those whose class or id occurs on the page |
| Site-specific | 10,520 rules for 8,298 sites | yes |
| Exceptions (`#@#`) | 340 | yes |
| `$generichide` sites | 154 | yes (no generic rules there) |
| Extended (`:-abp-contains`, `:has-text` …) | 294 | **no** (D-044) |
| With actions (`:remove()`, `:style()`) | 44 | no |
| Scriptlets (`+js(…)`, EasyPrivacy) | 34 | **no** (D-043, waits for D-017) |
| Rejected by the parser | 1 | — |

`:-abp-has(…)` is translated to standard `:has(…)`. Sorting both lists takes 45 ms (release build).

Without its CSS-validation feature, adblock-rust does not validate selectors. UNTRACE therefore refuses any selector containing `{`, `}`, `/*` or a leading `@`. Such a selector could carry declarations, and with them `url(…)` requests, out of the rule. The engine's CSS parser then drops any remaining invalid rule on its own.

## Cost: which way to apply generic rules (D-015 budget)

Test page: 3,000 elements, 800 distinct classes, 8 cross-origin frames, all under a strict CSP (`default-src 'self'`, no inline script or style). Nine rounds, with the order of variants rotated every round. One warm-up load is not counted.

| Variant | Page load event (median) | Setup in the page | Setup per frame |
|---|---|---|---|
| No script | 268 ms | — | — |
| Script that exits at once (parse only, 0.84 MB) | 308 ms | 0.2 ms | 0.3 ms |
| **Observe classes and ids** (0.84 MB) | **309 ms** | **1.4 ms** | **2.2 ms** |
| Apply every generic rule (1.36 MB) | 383 ms | 7.8 ms | 8.2 ms |

- **The cost is the script's size**, about 4.4 ms per document (9 documents: +40 ms); applying the rules by observation adds almost nothing to that. Applying all generic rules costs about three times as much. Observation is chosen, as planned.
- **Correct in every variant that hides:**
  - the generic class rule, the generic id rule and the site-specific rule hide their elements;
  - all 8 cross-origin frames hide theirs;
  - the control stays visible;
  - the strict CSP produced 0 violation reports.
- Real pages are larger and slower than this local page, so the share should be smaller. The real-site measurement (cosmetic on vs off) is the M6 exit test.

## Real sites: hiding on vs off (2026-11-23)

Method as in M3 and M5 (`compat.exe … paired-hide`). Both engines filter with the bundled lists, without the network layer; "off" has hiding switched off. 53-site corpus, two rounds, fresh profiles, the first engine alternating.

**First design: one 0.84 MB script in every document** (`paired-hide-one-script.json`)

| | Pairs | Median off → on | p95 off → on | Median of per-pair ratios |
|---|---|---|---|---|
| Host-timed | 101 | 875 → 909 ms (+3.9 %) | 2,674 → 2,715 ms (+1.5 %) | 1.046 |
| Load event | 99 | 1,008 → 1,104 ms (+9.5 %) | 2,405 → 2,694 ms (**+12.0 %**) | 1.043 |

The load-event p95 was over budget. The spike then showed the cost is the script's size, not its work:
- a near-empty script costs nothing;
- 725 KB costs about 7 ms per document;
- a never-run copy of the same text costs the same, so lazy loading cannot help.

**Second design: split.** Every document gets 0.23 MB of generic rules. The visited site's own rules come in a 0.7 KB script registered per navigation, applied again when content starts loading in case registration came late. On the spike page that is +6 ms for 9 documents, against +77 ms before. Real sites (`paired-hide.json`, plus `tail.json`: the 8 slowest sites × 6):

| | Pairs | Median off → on | p95 off → on | Median of per-pair ratios |
|---|---|---|---|---|
| Corpus, host-timed | 101 | 892 → 934 ms (+4.7 %) | 2,568 → 2,560 ms (−0.3 %) | 1.039 |
| Corpus, load event | 97 | 1,033 → 1,024 ms (−0.9 %) | 2,101 → 2,671 ms (+27.1 %) | 1.072 |
| Corpus + tail, load event | 149 | 1,199 → 1,217 ms (+1.5 %) | 4,456 → 4,803 ms (+7.8 %) | — |
| Corpus + tail, host-timed | 143 | 1,156 → 1,308 ms | 4,462 → 5,188 ms (+16.3 %) | — |

**Reading:**
- The network was much noisier than during M3 and M5. Single sites swing by seconds in both directions, and the first load of a pair is often the slow one, whichever engine it is. For example, youtube.com's off-load median was 4,822 ms and its on-load median 2,070 ms.
- So the p95 moves between −0.3 % and +27 % depending on the run and the measure; it cannot settle the budget either way.
- The steadiest figure, the median of per-pair ratios, puts the typical cost of hiding at **about 4 %** (1.039–1.072).
- open.spotify.com looked consistently slower in the tail run (6 of 6). Spotify is a `$generichide` site, where UNTRACE applies no generic rules and runs no observer. Eight more pairs each, with and without the per-site script (`spotify-full.json`, `spotify-nosite.json`), showed hiding slower in 3 of 8 and 4 of 8: no Spotify-specific cost.
- **Status: the M6 exit criterion "no regression in page-load budget" is not demonstrated by p95 on this network; the typical cost (~4 %) is within the 10 % budget.** The product owner accepted M6 on that basis (2026-11-23); the p95 may be re-measured later on a quieter network.

## In the product

- Two scripts per tab: generic rules (0.23 MB) registered before the tab's first page loads (pages wait for it at most 3 s); the visited site's own rules (about 1 KB) registered when a top-level navigation starts, and applied again when content starts loading if the registration came too late. Frames from other sites get only generic rules.
- It is regenerated when the lists, the switch or a site exception change. Pages already open keep their state until they reload.
- Each list adds two canary rules: a generic class and a rule for `untrace.invalid`. Settings reads the switch back from them and from the script on every tab; self-checks 45 and 46 test hiding end to end.
