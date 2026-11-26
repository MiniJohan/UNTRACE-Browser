# UNTRACE privacy notice

UNTRACE has no accounts, no cloud service and no analytics. It does not collect information about you, and nothing you do in it is sent to the people who make UNTRACE.

## What stays on your computer

Everything UNTRACE stores is in `%LOCALAPPDATA%\UNTRACE`, readable only by your Windows account:

- **Settings:** your choices, including sites you made exceptions for.
- **Bookmarks:** the pages you bookmarked, with their titles, folders and the icon each page showed. They stay until you remove them; deleting browsing data does not remove them. Bookmarks added from temporary tabs are kept too.
- **Activity log:** what UNTRACE did and changed (settings, list updates, clearing, checks, errors). It never records addresses or sites, and it holds about 1 MB at most; older entries are dropped.
- **Block lists:** the lists UNTRACE blocks and warns with.
- **The browser engine's data:**
  - cookies and site data;
  - the cache, deleted when you close UNTRACE unless you turn that off;
  - permissions you saved for sites.
  The engine's own history is cleared before each session; UNTRACE keeps no browsing history of its own.
- **Crash reports:** kept on this computer only and deleted after 7 days. They are never uploaded.

Settings › Your data lists what is stored and deletes it, per category or per site. Temporary tabs keep nothing after they close.

## What leaves your computer, and to whom

- **Websites you visit** see your IP address and what every browser sends. UNTRACE is not a VPN. Sites can also tell that UNTRACE runs on Microsoft's WebView2 engine.
- **Name lookups (DNS):** with Encrypted DNS on Automatic, your usual DNS provider sees the names you look up, encrypted when Windows knows how. In Strict mode, only the provider you chose sees them: Quad9, Cloudflare, Mullvad or your own server.
- **Block-list updates:** while "Update block lists automatically" is on, UNTRACE downloads the lists from their maintainers:
  - `easylist.to` for EasyList and EasyPrivacy;
  - `ublockorigin.github.io` (GitHub) for uBlock Origin's lists;
  - `malware-filter.gitlab.io` for the malware and phishing lists.
  These requests carry nothing about you beyond what any download does: your IP address and a standard request.
- **Update checks:** while "Check for UNTRACE updates" is on, UNTRACE asks GitHub once a day whether a new version exists, and downloads it from GitHub only when you choose to install it.
- **Nothing else from UNTRACE itself:** no usage statistics, no crash uploads, no identifiers. Bookmarks are never sent anywhere; importing and exporting them only reads or writes the file you choose.

## Microsoft's WebView2 engine

UNTRACE shows pages with Microsoft Edge WebView2, a part of Windows:
- **Diagnostic data:** the engine sends Microsoft the diagnostic data that your Windows diagnostic-data setting requires. UNTRACE cannot turn this off.
- **Background requests:** while Encrypted DNS is on, UNTRACE's network layer blocks the engine's own background requests, such as to Microsoft's configuration service, and lists them in Diagnostics.
- **SmartScreen:** Microsoft's SmartScreen site check is off by default, so the sites you visit are not sent to Microsoft for checking.

## Your choices

Every protection is explained in Settings, with what it does not do, and can be turned off. Diagnostics shows what UNTRACE could verify, and can save a security report. The report never contains the sites you visited.

Uninstalling UNTRACE removes the program. The uninstaller asks whether to delete `%LOCALAPPDATA%\UNTRACE` too.

## Questions

Report security problems privately as described in SECURITY.md. Everything else goes to the issue tracker of UNTRACE's GitHub repository.
