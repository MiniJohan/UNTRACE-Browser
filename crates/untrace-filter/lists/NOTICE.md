# Bundled block lists — sources and licences

UNTRACE ships unmodified snapshots of these lists so filtering works on the first start without a
network connection (D-032). When "Update block lists automatically" is on, newer versions are
downloaded from the same addresses, validated, and used instead. Diagnostics › Block lists shows
the version in use, its source and its licence.

| File | List | Source | Licence | Changes |
|---|---|---|---|---|
| `easylist.txt` | **EasyList** by The EasyList authors | https://easylist.to/easylist/easylist.txt | Dual-licensed GPLv3 / **CC BY-SA 3.0**; UNTRACE uses it under [CC BY-SA 3.0](https://creativecommons.org/licenses/by-sa/3.0/) | None. Network rules and element-hiding rules are used (M6); scriptlets and extended rules are not (D-043, D-044). |
| `easyprivacy.txt` | **EasyPrivacy** by The EasyList authors | https://easylist.to/easylist/easyprivacy.txt | As EasyList | None. As above. |
| `urlhaus-domains.txt` | **Online Malicious Domains Blocklist** (urlhaus-filter) by the malware-filter project, from [URLhaus](https://urlhaus.abuse.ch/) by abuse.ch | https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt | Project: CC0 1.0 and MIT; URLhaus data: [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) | None. |
| `phishing-domains.txt` | **Phishing Domains Blocklist** (phishing-filter) by the malware-filter project, from OpenPhish, PhishTank and IPThreat | https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt | Filters: [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). OpenPhish and PhishTank data are provided free of charge under their own terms (https://openphish.com/terms.html, https://phishtank.org/faq.php) — **to be reviewed before the first public release** (D-032). | None. |

Snapshot dates are in each file's header (`Version:` / `Updated:`). The lists are data files
distributed alongside UNTRACE; they are not part of UNTRACE's code and keep their own licences
regardless of UNTRACE's licence (D-017).

Neither the EasyList authors, the malware-filter project, abuse.ch, OpenPhish, PhishTank nor
IPThreat endorse UNTRACE.
