# Bundled resources — sources and licences

| File | What | Source | Licence | Changes |
|---|---|---|---|---|
| `ubo-scriptlets.json` | uBlock Origin's scriptlets (153 functions; 34 marked trusted), by Raymond Hill and contributors | uBlock Origin 1.77.2, https://github.com/gorhill/uBlock/tree/1.77.2/src/js/resources | GPL-3.0-or-later ([text](../lists/LICENSE-uAssets.txt)) | Repackaged only: each function's source, unchanged, as a resource entry for the matching library (`scripts/ubo-scriptlets/build.mjs`). |

The source of every scriptlet is the function text inside the file (base64), and the release it
comes from is linked above. UNTRACE's own code stays under the MPL-2.0 (D-017, D-057).

The uBlock Origin project does not endorse UNTRACE.
