# D-003 experiment — one shared WebView2 environment vs. a dedicated content environment

Date: 2026-11-21 · UNTRACE 0.1.0 (M1), Tauri 2.12.7 / wry 0.57.3, WebView2 Runtime 157.0.4341.60, Windows 11 build 26300.

**Question.** Content views currently run in their own WebView2 environment, separate from the UI view's (D-003). Could they instead run in the environment Tauri creates for the UI view, using their own profile? Would that save memory, and could UNTRACE still control everything it must?

**Method.**
- Experimental switch `UNTRACE_EXPERIMENT_SHARED_ENV=1`: content views are created from Tauri's environment (`ContentHost::with_environment`) with profile `standard`, instead of in a dedicated environment.
- Memory: [measure.ps1](measure.ps1). 3 runs per mode, alternated, each with a fresh data folder. Each run loads the same loopback page in the first tab, waits 8 s, then sums every `msedgewebview2.exe` process belonging to that run. Raw data: [results.json](results.json).
- Function: the 12-check `--self-check` in both modes. Reports: [selfcheck-shared.json](selfcheck-shared.json), [selfcheck-dedicated.json](selfcheck-dedicated.json).
- Control: the WebView2 environment options wry 0.57.3 sets (`src/webview2/mod.rs`, `create_environment`).

## Memory

| Mode | Processes | Browser processes | Private (median) | Working set (median) |
|---|---|---|---|---|
| Dedicated (current) | 12 | 2 | **395 MB** (332–396) | **652 MB** |
| Shared | 7 | 1 | **275 MB** (274–285) | **397 MB** |
| **Saving** | −5 | −1 | **≈ 120 MB (−30 %)** | **≈ 255 MB (−39 %)** |

The page loaded in all 6 runs. The saving is the second browser, GPU, utility and crash-handler process group. Renderers are unaffected.

## Function (self-check)

| Check | Dedicated | Shared |
|---|---|---|
| 11 other checks (globals, host bridge, autofill, SmartScreen, history, developer tools, UI lock, layout, …) | pass | pass |
| **Crash reports stay on this device** | pass | **fail** |

Content views get no Tauri globals even in Tauri's environment: Tauri injects its scripts per webview, not per environment.

## Control over the shared environment

| Option | Needed for | Controllable through Tauri 2.12 / wry 0.57? |
|---|---|---|
| Custom crash reporting | D-013 (crash dumps stay local) | **No.** wry never sets it, and Tauri exposes no option. |
| Browser arguments | M5 network layer (`--proxy-server`) | Yes (`additional_browser_args`). But wry's default `--disable-features=…msSmartScreenProtection` is replaced and must be restated. That default also stops users opting into SmartScreen (D-012). |
| Tracking prevention | M4 | Yes, in effect: wry leaves WebView2's default (on). |
| Extensions | D-022 (off) | Yes (`browser_extensions_enabled`). |

Other differences:
- **Resilience.** In shared mode, a browser-process failure takes down the UI view as well as the pages. In dedicated mode the UI survives and can report the error.
- **Data layout.** In shared mode the content profile lives inside the UI view's data folder.

## Decision

**Keep the dedicated content environment** (D-003 accepted). Sharing saves about 120 MB of private memory and is otherwise equivalent. But with Tauri 2.12 / wry 0.57 it cannot keep crash dumps local, so it would break D-013, which is a product commitment, not a preference.

**Revisit when** Tauri/wry exposes WebView2's custom crash reporting option ([upstream-request.md](upstream-request.md) is a ready-to-post request). Then switch to the shared environment, restate the browser arguments explicitly, and re-run this script and the self-check.

The experimental switch stays in the code for that re-test. The self-check fails while it is on, so it cannot ship by accident.
