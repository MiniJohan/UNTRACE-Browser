//! uBlock Origin's list directives (`!#if`, `!#else`, `!#endif`), 2026-11-26.
//!
//! uBlock Origin's lists keep variants for different browsers in conditional blocks. The
//! matching library reads `!` lines as comments, so it would use every branch, Firefox- and
//! Safari-only rules included. UNTRACE keeps the branches uBlock Origin itself uses on a
//! Chromium browser that cannot rewrite page HTML: that is what UNTRACE is.
//!
//! One exception, found on a real site (D-057): on Chromium, uBlock Origin matches some ad
//! networks with regular expressions that use lookahead (`(?=…)`), which the matching library
//! cannot evaluate, so those rules never match. Safari has the same limitation, and the lists
//! carry lookahead-free versions of these rules for it. UNTRACE also takes the regular-
//! expression network rules of Safari branches, and nothing else from them.

use std::borrow::Cow;

/// Conditions that are true for UNTRACE. Anything else (`env_firefox`, `env_safari`,
/// `env_mobile`, `env_mv3`, `ext_ubol`, `cap_html_filtering`, `cap_ipaddress`, …) is false.
const CHROMIUM: &[&str] = &["env_chromium", "ext_ublock", "cap_user_stylesheet"];
/// The same, as uBlock Origin on Safari: used only for regular-expression network rules.
const SAFARI: &[&str] = &["env_safari", "ext_ublock", "cap_user_stylesheet"];

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

/// One open `!#if`: is its branch kept for Chromium, and for Safari (parents included)?
#[derive(Clone, Copy)]
struct Open {
    parent: (bool, bool),
    cond: (bool, bool),
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
            .map_or((true, true), |o| (o.parent.0 && o.cond.0, o.parent.1 && o.cond.1))
    };
    for line in text.lines() {
        let t = line.trim();
        if let Some(cond) = t.strip_prefix("!#if ") {
            let parent = active(&stack);
            stack.push(Open {
                parent,
                cond: (eval(cond, CHROMIUM), eval(cond, SAFARI)),
            });
        } else if t == "!#else" {
            if let Some(top) = stack.last_mut() {
                top.cond = (!top.cond.0, !top.cond.1);
            }
        } else if t == "!#endif" {
            stack.pop();
        } else {
            let (chromium, safari) = active(&stack);
            if chromium || (safari && is_regex_network_rule(t)) {
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
    fn unbalanced_directives_do_not_panic() {
        let _ = preprocess("!#endif\n!#else\nx\n!#if\n!#if (((\ny\n");
    }
}
