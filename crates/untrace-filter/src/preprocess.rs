//! uBlock Origin's list directives (`!#if`, `!#else`, `!#endif`), 2026-11-26.
//!
//! uBlock Origin's lists keep variants for different browsers in conditional blocks. The
//! matching library reads `!` lines as comments, so it would use every branch, Firefox- and
//! Safari-only rules included. UNTRACE keeps the branches uBlock Origin itself uses on a
//! Chromium browser that cannot rewrite page HTML: that is what UNTRACE is.
//!
//! One exception, found on a real site (D-057, D-058): on Chromium, uBlock Origin matches some
//! ad networks with regular expressions that use lookahead (`(?=…)`), which the matching
//! library cannot evaluate. Safari and uBlock Origin Lite have the same limitation, and the
//! lists carry lookahead-free versions of these rules for them. UNTRACE also takes the
//! regular-expression network rules of Safari and uBlock Origin Lite branches, and nothing
//! else from them.
//!
//! D-058: the matching library fuses rules that have the same options into one set of regular
//! expressions. One expression it cannot compile makes the whole set fail, and every rule in it
//! stops matching, the working lookahead-free versions included. [`network_text`] therefore
//! drops, from every Adblock-format list, the regular-expression rules the library cannot
//! compile: they never matched anything, and now they no longer disable the others.

use std::borrow::Cow;

/// Conditions that are true for UNTRACE. Anything else (`env_firefox`, `env_safari`,
/// `env_mobile`, `env_mv3`, `ext_ubol`, `cap_html_filtering`, `cap_ipaddress`, …) is false.
const CHROMIUM: &[&str] = &["env_chromium", "ext_ublock", "cap_user_stylesheet"];
/// The same, as uBlock Origin on Safari: used only for regular-expression network rules.
const SAFARI: &[&str] = &["env_safari", "ext_ublock", "cap_user_stylesheet"];
/// The same, as uBlock Origin Lite on Chromium (Manifest V3): regular-expression network rules
/// only.
const UBOL: &[&str] = &["env_chromium", "env_mv3", "ext_ubol", "cap_user_stylesheet"];
/// The three readings of each branch: Chromium (everything), Safari and uBlock Origin Lite
/// (regular-expression network rules only).
const PLATFORMS: [&[&str]; 3] = [CHROMIUM, SAFARI, UBOL];

/// Evaluate one condition: identifiers, `!`, `&&`, `||` and parentheses.
fn eval(expr: &str, truths: &[&str]) -> bool {
    let tokens = tokenize(expr);
    let mut pos = 0;
    let v = or(&tokens, &mut pos, truths);
    // Anything left over means the condition was not understood: treat it as false, as an
    // unknown condition is.
    v && pos == tokens.len()
}

fn tokenize(expr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = expr.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {}
            '(' | ')' | '!' => out.push(c.to_string()),
            '&' | '|' => {
                if chars.peek() == Some(&c) {
                    chars.next();
                }
                out.push(format!("{c}{c}"));
            }
            _ => {
                let mut id = c.to_string();
                while let Some(&n) = chars.peek() {
                    if n.is_alphanumeric() || n == '_' || n == '-' || n == '.' {
                        id.push(n);
                        chars.next();
                    } else {
                        break;
                    }
                }
                out.push(id);
            }
        }
    }
    out
}

fn or(t: &[String], pos: &mut usize, truths: &[&str]) -> bool {
    let mut v = and(t, pos, truths);
    while t.get(*pos).map(String::as_str) == Some("||") {
        *pos += 1;
        let r = and(t, pos, truths);
        v = v || r;
    }
    v
}

fn and(t: &[String], pos: &mut usize, truths: &[&str]) -> bool {
    let mut v = unary(t, pos, truths);
    while t.get(*pos).map(String::as_str) == Some("&&") {
        *pos += 1;
        let r = unary(t, pos, truths);
        v = v && r;
    }
    v
}

fn unary(t: &[String], pos: &mut usize, truths: &[&str]) -> bool {
    match t.get(*pos).map(String::as_str) {
        Some("!") => {
            *pos += 1;
            !unary(t, pos, truths)
        }
        Some("(") => {
            *pos += 1;
            let v = or(t, pos, truths);
            if t.get(*pos).map(String::as_str) == Some(")") {
                *pos += 1;
            }
            v
        }
        Some(id) => {
            *pos += 1;
            truths.contains(&id)
        }
        None => false,
    }
}

/// A network rule written as a regular expression (`/…/$…`, or an exception `@@/…/$…`).
fn is_regex_network_rule(line: &str) -> bool {
    let l = line.strip_prefix("@@").unwrap_or(line);
    l.starts_with('/') && !l.contains("##") && !l.contains("#@#") && (l.contains("/$") || l.ends_with('/'))
}

/// The regular expression of a network rule written as one, as the matching library reads it:
/// the text between the slashes before the last `$` (which starts the options), with `\/` and
/// `\:` unescaped. `None` for any other line.
fn rule_regex(line: &str) -> Option<String> {
    if !is_regex_network_rule(line) {
        return None;
    }
    let l = line.strip_prefix("@@").unwrap_or(line);
    let pattern = l.rfind('$').map_or(l, |i| &l[..i]);
    (pattern.len() > 1 && pattern.ends_with('/'))
        .then(|| pattern[1..pattern.len() - 1].replace("\\/", "/").replace("\\:", ":"))
}

/// Can the matching library compile this regular expression? It uses the same library, built
/// the same way (byte matching, no Unicode classes).
fn compiles(re: &str) -> bool {
    regex::bytes::RegexBuilder::new(re).unicode(false).build().is_ok()
}

/// A regular-expression network rule the matching library cannot compile (lookahead,
/// look-behind, back-references, …).
fn unsupported_regex_rule(line: &str) -> bool {
    rule_regex(line.trim()).is_some_and(|re| !compiles(&re))
}

/// One open `!#if`: is its branch kept for Chromium, Safari and uBlock Origin Lite (parents
/// included)?
#[derive(Clone, Copy)]
struct Open {
    parent: [bool; 3],
    cond: [bool; 3],
}

/// Drop the lines of branches that do not apply. Text without directives is returned as is.
pub fn preprocess(text: &str) -> Cow<'_, str> {
    if !text.contains("!#if") {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut stack: Vec<Open> = Vec::new();
    let active = |stack: &[Open]| {
        stack
            .last()
            .map_or([true; 3], |o| std::array::from_fn(|i| o.parent[i] && o.cond[i]))
    };
    for line in text.lines() {
        let t = line.trim();
        if let Some(cond) = t.strip_prefix("!#if ") {
            let parent = active(&stack);
            stack.push(Open {
                parent,
                cond: PLATFORMS.map(|truths| eval(cond, truths)),
            });
        } else if t == "!#else" {
            if let Some(top) = stack.last_mut() {
                top.cond = top.cond.map(|c| !c);
            }
        } else if t == "!#endif" {
            stack.pop();
        } else {
            let [chromium, safari, ubol] = active(&stack);
            if chromium || ((safari || ubol) && is_regex_network_rule(t)) {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    Cow::Owned(out)
}

/// A list's text as the builders read it: uBlock Origin's lists with their directives applied.
pub fn list_text<'a>(s: &crate::engine::Source<'a>) -> Cow<'a, str> {
    if s.id.is_ublock() {
        preprocess(s.text)
    } else {
        Cow::Borrowed(s.text)
    }
}

/// A list's text as the network builders (requests, pop-ups) read it: [`list_text`], without
/// the regular-expression rules the matching library cannot compile (D-058).
pub fn network_text<'a>(s: &crate::engine::Source<'a>) -> Cow<'a, str> {
    without_unsupported_regex(list_text(s))
}

/// `text` without the regular-expression network rules the matching library cannot compile.
pub(crate) fn without_unsupported_regex(text: Cow<'_, str>) -> Cow<'_, str> {
    let bad: std::collections::HashSet<usize> = text
        .lines()
        .enumerate()
        .filter(|(_, l)| unsupported_regex_rule(l))
        .map(|(n, _)| n)
        .collect();
    if bad.is_empty() {
        return text;
    }
    let mut out = String::with_capacity(text.len());
    for (_, line) in text.lines().enumerate().filter(|(n, _)| !bad.contains(n)) {
        out.push_str(line);
        out.push('\n');
    }
    Cow::Owned(out)
}

/// How many regular-expression network rules of this text the matching library cannot compile.
pub fn unsupported_regex_rules(text: &str) -> usize {
    text.lines().filter(|l| unsupported_regex_rule(l)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditions_are_those_of_a_chromium_browser_without_html_filtering() {
        let e = |x| eval(x, CHROMIUM);
        assert!(e("env_chromium"));
        assert!(!e("env_firefox"));
        assert!(e("!cap_html_filtering"));
        assert!(e("!env_mobile && env_chromium"));
        assert!(e("env_firefox || env_chromium"));
        assert!(!e("(env_firefox || env_safari) && env_chromium"));
        assert!(e("!(env_mv3 || ext_ubol)"));
        assert!(!e("something_new"));
        assert!(!e("env_chromium )"), "not understood");
    }

    #[test]
    fn branches_nest_and_else_flips() {
        let text = "a\n\
                    !#if env_firefox\n\
                    firefox-only\n\
                    !#else\n\
                    not-firefox\n\
                    !#if cap_html_filtering\n\
                    html\n\
                    !#else\n\
                    scriptlet-path\n\
                    !#endif\n\
                    !#endif\n\
                    !#if env_mobile\n\
                    !#if env_chromium\n\
                    nested-in-false\n\
                    !#else\n\
                    also-false\n\
                    !#endif\n\
                    !#endif\n\
                    z\n";
        assert_eq!(preprocess(text), "a\nnot-firefox\nscriptlet-path\nz\n");
        assert!(matches!(preprocess("no directives\n"), Cow::Borrowed(_)));
    }

    #[test]
    fn safari_branches_give_only_their_regular_expression_rules() {
        let text = "!#if env_safari\n\
                    /^https:\\/\\/[a-z]+\\.cfd\\/[a-z][0-9A-Za-z]+\\/[0-9]+$/$script,3p,match-case\n\
                    @@/^https:\\/\\/ok\\.example\\/[0-9]+/$image\n\
                    ||safari-only.example^\n\
                    example.com##.safari-only\n\
                    !#else\n\
                    /^https:\\/\\/[a-z]+\\.cfd\\/(?=x)/$script\n\
                    !#endif\n\
                    !#if env_firefox\n\
                    /^https:\\/\\/firefox\\.example\\//$script\n\
                    !#endif\n";
        assert_eq!(
            preprocess(text),
            "/^https:\\/\\/[a-z]+\\.cfd\\/[a-z][0-9A-Za-z]+\\/[0-9]+$/$script,3p,match-case\n\
             @@/^https:\\/\\/ok\\.example\\/[0-9]+/$image\n\
             /^https:\\/\\/[a-z]+\\.cfd\\/(?=x)/$script\n"
        );
    }

    #[test]
    fn ubol_branches_give_only_their_regular_expression_rules() {
        let text = "!#if ext_ubol\n\
                    /^https:\\/\\/[a-z]{2}\\.[a-z]{7,14}\\.com\\/[rt][0-9A-Za-z]{10,16}\\/[A-Za-z]{4,5}(?:\\?|$)/$script,3p,match-case\n\
                    ||ubol-only.example^\n\
                    !#endif\n\
                    !#if !ext_ubol\n\
                    ||not-ubol.example^\n\
                    !#endif\n";
        assert_eq!(
            preprocess(text),
            "/^https:\\/\\/[a-z]{2}\\.[a-z]{7,14}\\.com\\/[rt][0-9A-Za-z]{10,16}\\/[A-Za-z]{4,5}(?:\\?|$)/$script,3p,match-case\n\
             ||not-ubol.example^\n"
        );
        let e = |x| eval(x, UBOL);
        assert!(e("ext_ubol") && e("env_chromium") && e("env_mv3"));
        assert!(!e("ext_ublock") && !e("env_safari"));
    }

    #[test]
    fn regular_expressions_the_library_cannot_compile_are_dropped() {
        let good = "/^https:\\/\\/[a-z]+\\.cfd\\/[a-z][0-9A-Za-z]{10,22}\\/(\\d{6}|[A-Za-z]{5})$/$script,3p,match-case";
        let lookahead = "/^https:\\/\\/(?:[0-9a-z]+\\.){1,2}cfd\\/[a-z](?=[a-z]*[0-9A-Z])[0-9A-Za-z]{10,27}\\/(?:\\d{6}|[A-Za-z]{5})$/$script,xhr,3p,match-case";
        let exception = "@@/^https:\\/\\/ok\\.example\\/(?!x)/$image";
        let backreference = "/(a)\\1/$script";
        assert!(!unsupported_regex_rule(good));
        assert!(unsupported_regex_rule(lookahead));
        assert!(unsupported_regex_rule(exception));
        assert!(unsupported_regex_rule(backreference));
        // Not regular-expression network rules: left to the library.
        for other in [
            "||ads.example^$script",
            "/banner/*/img^",
            "/ad.js",
            "example.com##.ad(?=x)",
            "! /(?=x)/$script",
            "/^https:\\/\\/a\\.example\\/(?=x)$/",
        ] {
            assert!(!unsupported_regex_rule(other), "{other}");
        }
        let text = format!("||a.example^\n{lookahead}\n{good}\n{exception}\nexample.com##.ad\n");
        assert_eq!(
            without_unsupported_regex(Cow::Borrowed(&text)),
            format!("||a.example^\n{good}\nexample.com##.ad\n")
        );
        assert_eq!(unsupported_regex_rules(&text), 2);
        let clean = "||a.example^\n/ad.js\n";
        assert!(matches!(
            without_unsupported_regex(Cow::Borrowed(clean)),
            Cow::Borrowed(_)
        ));
    }

    /// The matching library fuses rules with the same options into one set of regular
    /// expressions. After filtering, every such set in the bundled lists must compile (a set
    /// can also fail by growing past the library's size limit).
    #[test]
    fn regular_expression_sets_of_the_bundled_lists_compile() {
        use std::collections::HashMap;
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        let mut dropped = 0;
        for id in crate::catalog::ListId::ALL {
            let i = crate::info(id);
            if i.format != crate::catalog::Format::Adblock {
                continue;
            }
            let s = crate::engine::Source { id, text: i.bundled };
            dropped += unsupported_regex_rules(&list_text(&s));
            for line in network_text(&s).lines() {
                let Some(re) = rule_regex(line.trim()) else { continue };
                let options = line.rfind('$').map_or("", |n| &line[n + 1..]);
                // Rules the library never fuses: per-site, per-destination, redirects, CSP.
                if ["domain=", "from=", "to=", "redirect", "csp"]
                    .iter()
                    .any(|o| options.contains(o))
                {
                    continue;
                }
                let mut opts: Vec<&str> = options.split(',').collect();
                opts.sort_unstable();
                let key = format!("{}{}", line.starts_with("@@"), opts.join(","));
                groups.entry(key).or_default().push(re);
            }
        }
        assert!(dropped > 0, "the bundled uBlock Origin lists have lookahead rules");
        for (key, res) in &groups {
            let set = regex::bytes::RegexSetBuilder::new(res).unicode(false).build();
            assert!(set.is_ok(), "{key}: {} rules: {set:?}", res.len());
        }
    }

    #[test]
    fn unbalanced_directives_do_not_panic() {
        let _ = preprocess("!#endif\n!#else\nx\n!#if\n!#if (((\ny\n");
    }
}
