//! Element-hiding rules from a list: sorting, the selector safety check, and the scripts and
//! style sheets generated from them. No generated CSS may carry a declaration of its own.
#![no_main]
use libfuzzer_sys::fuzz_target;
use untrace_filter::{
    ListId,
    cosmetic::{CosmeticRules, GenericMode, ScriptOptions, site_script},
    engine::Source,
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let rules = CosmeticRules::build(&[Source { id: ListId::EasyList, text }]);
    let host = text.lines().next().unwrap_or("example.com").trim();
    let _ = rules.for_host(host);
    let _ = rules.for_host("example.com");
    for h in [host, "example.com", "www.example.co.uk"] {
        if let Some(css) = rules.site_css(h) {
            // Every rule is "<selector>{display:none!important}"; a selector that could close
            // the block or open a comment would let a list inject other CSS (e.g. url()).
            for rule in css.split("{display:none!important}") {
                assert!(!rule.contains(['{', '}']), "rule {rule:?} in {css:?}");
                assert!(!rule.contains("/*"), "comment in {rule:?}");
            }
            let js = site_script(h, &css);
            assert!(!js.contains("</script"), "script end in site script");
        }
    }
    let o = ScriptOptions { generic: GenericMode::Observe, off_sites: vec![host.to_string()], debug: false, embed_site_rules: false };
    let _ = rules.script(&o);
});
