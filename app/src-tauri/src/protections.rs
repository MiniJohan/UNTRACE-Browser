//! The protections UNTRACE offers. Each appears only once the engine (or UNTRACE's own policy)
//! can enforce it and report its state.

use untrace_core::registry::{Kind, ProtectionDef, Scope};
use untrace_filter::catalog::{BLOCK_ADS_ID, BLOCK_TRACKERS_ID, UBLOCK_ID, WARN_MALWARE_ID, WARN_PHISHING_ID};
use untrace_webview::{
    DEVTOOLS_ID, HIDE_ELEMENTS_ID, HTTPS_ONLY_ID, LOCAL_NETWORK_ID, SLEEP_CHOICES, SLEEP_TABS_ID, STRIP_PARAMS_ID,
    TRACKING_LEVELS, TRACKING_PREVENTION_ID, WEBRTC_ID,
};

use crate::{
    network::{DNS_MODE_ID, DNS_MODES, DOH_PROVIDER_ID, DOH_PROVIDERS},
    privacy::{CLEAR_CACHE_ON_EXIT_ID, CLEAR_SITE_DATA_ON_EXIT_ID},
};

/// Shared by the two request-blocking lists.
const BLOCKING_LIMITS: &str = "Requests are blocked; the empty space an ad leaves behind is hidden by \
    \"Hide the space blocked ads leave\". WebSocket connections are not seen at this level (with \
    encrypted DNS on, the network layer still stops malware and phishing hosts). Requests made by \
    service and shared workers are matched without knowing their page, and site exceptions may \
    not apply to them. You can turn blocking off for one site in the page's site panel.";

pub fn defs() -> Vec<ProtectionDef> {
    vec![
        ProtectionDef {
            id: BLOCK_ADS_ID,
            group: "Blocking",
            title: "Block ads",
            explanation: "Requests for ads are blocked using EasyList, the most widely used ad list. Pages \
                          load less from ad networks, and UNTRACE counts what it blocked in the site panel.",
            limitations: BLOCKING_LIMITS,
            scope: Scope::View,
            kind: Kind::Toggle { default: true },
        },
        ProtectionDef {
            id: UBLOCK_ID,
            group: "Blocking",
            title: "uBlock Origin filters",
            explanation: "Adds the lists of the uBlock Origin project to EasyList and EasyPrivacy: ads and \
                          pop-ups on the sites EasyList misses (streaming and download sites among them), \
                          scam and fake-download pages, more trackers, and fixes for sites the lists would \
                          otherwise break. Its quick fixes are checked every 12 hours, as uBlock Origin does. \
                          It also runs the lists' scriptlets: uBlock Origin's small page scripts that remove what \
                          blocking requests cannot, such as YouTube's video ads, pop-up openers and anti-adblock \
                          walls. They run before the page's own scripts.",
            limitations: "The lists are written for the uBlock Origin extension. UNTRACE applies what its \
                          blocking engine supports: rules that rewrite addresses or responses (urlskip, \
                          replace, redirect-rule and others, about 5 % of the rules) are not applied. The lists \
                          and uBlock Origin's scriptlets (bundled with UNTRACE, updated with UNTRACE) are \
                          licensed under GPL-3.0 by their authors. Scriptlets run inside pages, as page scripts \
                          do; only uBlock Origin's own lists may use its \"trusted\" scriptlets. YouTube changes \
                          often: uBlock Origin's quick fixes usually follow within hours, but ads can return for \
                          a while. The same request-level limits as ad \
                          blocking apply, and \"Block ads and trackers\" in a site's panel turns them off \
                          for that site.",
            scope: Scope::View,
            kind: Kind::Toggle { default: true },
        },
        ProtectionDef {
            id: BLOCK_TRACKERS_ID,
            group: "Blocking",
            title: "Block trackers",
            explanation: "Requests to known trackers (analytics, pixels, session recorders) are blocked \
                          using EasyPrivacy.",
            limitations: "Only trackers on the list are recognised. Tracking done by the site itself, or \
                          through a tracker the list does not know yet, still works. Browser fingerprinting \
                          is not prevented, and sites can tell that UNTRACE runs on Microsoft's WebView2 \
                          engine: it says so with every request, and UNTRACE measured that this cannot be \
                          hidden consistently. The same request-level limits as ad blocking apply.",
            scope: Scope::View,
            kind: Kind::Toggle { default: true },
        },
        ProtectionDef {
            id: HIDE_ELEMENTS_ID,
            group: "Blocking",
            title: "Hide the space blocked ads leave",
            explanation: "Boxes and banners that held blocked ads are hidden, using the element-hiding rules of \
                          the lists you use (about 13,600 rules for every site and 10,500 for particular \
                          sites in EasyList). A small script added to every page applies them before the \
                          page shows, only for the class names and ids that actually occur on it.",
            limitations: "Takes effect on pages you open or reload after a change. Rules that need custom code \
                          are not applied: about 300 extended rules (such as \"hide this box if it says \
                          Sponsored\"). The lists' scriptlets run with their lists, whatever this switch says \
                          (see \"uBlock Origin filters\"). Pages can tell that elements were hidden. Turning blocking off for a site in its site panel \
                          turns hiding off there too.",
            scope: Scope::View,
            kind: Kind::Toggle { default: true },
        },
        ProtectionDef {
            id: crate::filters::AUTO_UPDATE_ID,
            group: "Blocking",
            title: "Update block lists automatically",
            explanation: "UNTRACE downloads new versions of the lists you use when each list says it is due \
                          (every 12 hours for malware and phishing, every 4 days for ads and trackers), checks \
                          that each download really is that list, and keeps the previous copy.",
            limitations: "Each update connects to the list's publisher (easylist.to, malware-filter.gitlab.io), \
                          which sees your IP address and that UNTRACE is asking. No cookies or identifiers are \
                          sent. When this is off, the lists shipped with UNTRACE (or the last download) stay in \
                          use and grow outdated — the malware and phishing lists within days.",
            scope: Scope::App,
            kind: Kind::Toggle { default: true },
        },
        ProtectionDef {
            id: WARN_MALWARE_ID,
            group: "Security",
            title: "Warn about malware sites",
            explanation: "Before opening a site that currently spreads malware, UNTRACE stops and explains. \
                          You can go back, or continue to that site for this session. Parts of other pages \
                          that come from such sites are blocked. Uses the URLhaus list from abuse.ch.",
            limitations: "Only sites already reported are known; the list is updated about twice a day, so \
                          a brand-new malicious site is not on it yet. It lists whole sites, not single \
                          files on otherwise legitimate ones.",
            scope: Scope::View,
            kind: Kind::Toggle { default: true },
        },
        ProtectionDef {
            id: WARN_PHISHING_ID,
            group: "Security",
            title: "Warn about phishing sites",
            explanation: "Before opening a known phishing site (fake sign-in or payment pages), UNTRACE stops \
                          and explains. You can go back, or continue to that site for this session. Uses \
                          reports collected from OpenPhish, PhishTank and IPThreat.",
            limitations: "Phishing sites appear and disappear within hours; many are not reported before you \
                          meet them. Never rely on this alone: check the address before entering a password.",
            scope: Scope::View,
            kind: Kind::Toggle { default: true },
        },
        ProtectionDef {
            id: HTTPS_ONLY_ID,
            group: "Security",
            title: "HTTPS-only mode",
            explanation: "Pages are always loaded over an encrypted connection. If a site has no secure version, \
                          UNTRACE tells you and lets you continue over plain HTTP for that site, for this session only.",
            limitations: "Pages served from this computer (localhost) are exempt. Images and other parts of a page \
                          follow the engine's mixed-content rules. Permission to use plain HTTP is forgotten when \
                          UNTRACE closes.",
            scope: Scope::View,
            kind: Kind::Toggle { default: true },
        },
        ProtectionDef {
            id: LOCAL_NETWORK_ID,
            group: "Security",
            title: "Keep websites away from your local network",
            explanation: "Scripts, frames and images of a public website cannot reach this computer (localhost) or \
                          devices on your network, such as your router, printer or NAS, by their address or local \
                          name. UNTRACE blocks such requests and counts them in the site panel, where you can allow \
                          a site that needs it (a router or smart-home app, for example). With encrypted DNS on, a \
                          public name that points into your network is refused as well (DNS rebinding).",
            limitations: "The engine has no protection of its own here: UNTRACE measured that it allows every such \
                          request. Opening a local address yourself, or a link to one, always works, as in other \
                          browsers. With encrypted DNS off, a public name that points into your network is not \
                          caught. Requests from service workers are judged by the page they name. WebRTC (calls, \
                          peer-to-peer) is covered only while \"Keep WebRTC inside the network layer\" is on.",
            scope: Scope::View,
            kind: Kind::Toggle { default: true },
        },
        ProtectionDef {
            id: TRACKING_PREVENTION_ID,
            group: "Privacy",
            title: "Tracking prevention",
            explanation: "The engine's own protection against known trackers, using Microsoft's tracker list \
                          (in addition to EasyPrivacy). Balanced restricts what known trackers can store, \
                          including their third-party cookies, on sites you have not visited directly. Strict \
                          also stops most of them loading. Basic only acts on cryptomining and fingerprinting \
                          scripts.",
            limitations: "This is how UNTRACE restricts third-party cookies: only those of known trackers. The \
                          engine offers no way to block all third-party cookies in every frame and tab (D-010). \
                          Strict breaks some embedded videos, social widgets and sign-ins. The level is stored \
                          by the engine and applies to normal and temporary tabs alike.",
            scope: Scope::Profile,
            kind: Kind::Choice {
                options: &TRACKING_LEVELS,
                default: "balanced",
            },
        },
        ProtectionDef {
            id: STRIP_PARAMS_ID,
            group: "Privacy",
            title: "Remove tracking parameters from links",
            explanation: "Parameters that only identify the click or campaign that brought you to a page \
                          (utm_source, gclid, fbclid, msclkid and about 50 others) are removed from page and frame \
                          addresses before the request is sent, so neither the site nor its scripts receive \
                          them. The site panel shows what was removed.",
            limitations: "Only parameters on UNTRACE's reviewed list are removed; sites can invent new ones, or \
                          hide the same information in the path. Form submissions (POST) are left alone. Links \
                          you copy from a page still contain the parameters until you open them in UNTRACE.",
            scope: Scope::View,
            kind: Kind::Toggle { default: true },
        },
        ProtectionDef {
            id: CLEAR_CACHE_ON_EXIT_ID,
            group: "Privacy",
            title: "Delete the cache when UNTRACE closes",
            explanation: "Copies of pages, scripts and images are deleted every time you close UNTRACE, so they do \
                          not show where you have been. Sites load a little slower on the first visit after.",
            limitations: "Closing waits until the engine has finished (at most 10 seconds). If UNTRACE is ended \
                          another way (crash, power loss, Windows shutting down), the cache is deleted the next \
                          time it starts, before any page loads.",
            scope: Scope::App,
            kind: Kind::Toggle { default: true },
        },
        ProtectionDef {
            id: CLEAR_SITE_DATA_ON_EXIT_ID,
            group: "Privacy",
            title: "Delete cookies and site data when UNTRACE closes",
            explanation: "Every close starts you fresh: cookies, local storage, IndexedDB and service workers of \
                          normal tabs are deleted, and UNTRACE checks that no cookie is left. You will be signed \
                          out of every site.",
            limitations: "Off by default, so sign-ins keep working (D-014). Saved permission decisions are kept. \
                          If UNTRACE is ended another way, the data is deleted the next time it starts, before \
                          any page loads. Temporary tabs never keep site data anyway.",
            scope: Scope::App,
            kind: Kind::Toggle { default: false },
        },
        ProtectionDef {
            id: DNS_MODE_ID,
            group: "Network",
            title: "Encrypted DNS",
            explanation: "Decides who can see which sites you look up. With Automatic or Strict, every request of the \
                          engine passes through UNTRACE's network layer on this computer, which looks names up \
                          itself. Automatic encrypts lookups when your DNS server offers that (Windows knows the \
                          encrypted address of Quad9, Cloudflare and Google), and otherwise lets Windows look them \
                          up as before. Strict sends every lookup, encrypted, to the provider below and nowhere \
                          else. The network layer also stops connections to malware and phishing sites that the \
                          page-level check cannot see (such as WebSockets), blocks the engine's own background \
                          connections to Microsoft, and lists the hosts contacted this session in Diagnostics.",
            limitations: "Takes effect when you restart UNTRACE. Off: the engine looks names up itself, usually \
                          unencrypted, and also searches your network for a proxy (WPAD). The network layer relies \
                          on an engine option Microsoft does not support for production use; UNTRACE checks at \
                          every start that the engine's requests really pass through it, and opens no page if it \
                          cannot start. UNTRACE's own block-list downloads use Windows networking, so Windows \
                          looks up those two list hosts. WebRTC (calls, peer-to-peer) passes through the network \
                          layer only while \"Keep WebRTC inside the network layer\" is on. Your DNS provider still \
                          sees the names you look up, and sites still see your IP address: this is not a VPN. Your \
                          network can still see which sites you connect to: their addresses, and their names at \
                          the start of each encrypted connection (Encrypted Client Hello is not used).",
            scope: Scope::Environment,
            kind: Kind::Choice {
                options: &DNS_MODES,
                default: "automatic",
            },
        },
        ProtectionDef {
            id: DOH_PROVIDER_ID,
            group: "Network",
            title: "Provider for Strict",
            explanation: "Quad9 (Swiss non-profit; also refuses to resolve known malicious domains), Cloudflare (US) \
                          or Mullvad (Sweden), or your own DNS-over-HTTPS server. Each publishes its own privacy \
                          policy.",
            limitations: "Used only when Encrypted DNS is Strict. The provider sees every name you look up, but not \
                          what you do on the site. If it cannot be reached, names are not looked up and pages do \
                          not load: Strict never falls back. Names that only exist on your network (ending in \
                          .local, .lan or .home.arpa, or without a dot) are looked up by Windows.",
            scope: Scope::App,
            kind: Kind::Choice {
                options: &DOH_PROVIDERS,
                default: "quad9",
            },
        },
        ProtectionDef {
            id: WEBRTC_ID,
            group: "Network",
            title: "Keep WebRTC inside the network layer",
            explanation: "Calls, video chats and other WebRTC connections go only through UNTRACE's network layer. \
                          A page cannot use WebRTC to send data around it: no direct connections to other \
                          computers, to devices on your network or to this computer, and no name lookups outside \
                          encrypted DNS. UNTRACE measured that without this, a page could do all three.",
            limitations: "Takes effect when you restart UNTRACE, and only while Encrypted DNS is on (the network \
                          layer runs). Calls still work when the service relays them over TCP or TLS, as most large \
                          call services do, sometimes with a little more delay. Direct peer-to-peer connections, \
                          such as some file transfers, games or local tools, do not connect. Off: WebRTC connects \
                          directly, and encrypted DNS, the malware and phishing check of the network layer and \
                          local-network protection do not cover it.",
            scope: Scope::Environment,
            kind: Kind::Toggle { default: true },
        },
        ProtectionDef {
            id: crate::appupdate::AUTO_CHECK_ID,
            group: "Updates",
            title: "Check for UNTRACE updates",
            explanation: "Once a day UNTRACE asks GitHub, where its releases are published, whether a newer version \
                          exists, and tells you. You decide when to install it. Before an update runs, UNTRACE checks \
                          that it carries UNTRACE's signature for exactly that version; anything else is refused.",
            limitations: "GitHub sees your IP address and that you use UNTRACE, as with any download. The check uses \
                          Windows networking, not UNTRACE's network layer, like the block-list downloads. Off: you \
                          learn about new versions only from the release page. The browser engine is updated by \
                          Microsoft through Windows either way.",
            scope: Scope::App,
            kind: Kind::Toggle { default: true },
        },
        ProtectionDef {
            id: SLEEP_TABS_ID,
            group: "Performance",
            title: "Sleeping tabs",
            explanation: "Tabs you have not looked at for this long go to sleep: the browser engine stops their \
                          scripts and frees the memory it can, the way Microsoft Edge's sleeping tabs work. A \
                          sleeping tab looks dimmed and wakes as soon as you open it.",
            limitations: "A sleeping page does nothing until you open it: no new messages, notifications or \
                          updates in the background, and some pages reload or reconnect when they wake. Tabs \
                          playing sound, tabs whose site may use the camera or microphone, and tabs waiting for an \
                          answer never sleep. How much memory sleeping frees depends on the page.",
            scope: Scope::App,
            kind: Kind::Choice {
                options: &SLEEP_CHOICES,
                default: "30 minutes",
            },
        },
        ProtectionDef {
            id: DEVTOOLS_ID,
            group: "Developer",
            title: "Developer tools",
            explanation: "Lets you inspect pages with the built-in developer tools (F12, or right-click › Inspect).",
            limitations: "Off by default: it removes a common route for being talked into pasting code into a page. \
                          Applies to every open tab immediately. UNTRACE's own interface has no developer tools in \
                          release builds.",
            scope: Scope::View,
            kind: Kind::Toggle { default: false },
        },
    ]
}
