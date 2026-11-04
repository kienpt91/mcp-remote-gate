//! Making untrusted text safe for logs, and keeping credentials out of them.
//!
//! Everything that a client or the upstream server wrote and that reaches a log line goes
//! through [`escape_control`], so it cannot forge log lines or drive a terminal. Everything that
//! can carry a secret goes through [`redact_text`] or [`redact_value`] first. The redaction is
//! heuristic (known key prefixes, long mixed tokens, sensitive key names); it lowers the chance of
//! a leak, it does not make logging arguments safe, which is why that is opt-in.

use crate::json::Value;

pub const REDACTED: &str = "[redacted]";

/// Characters that are invisible or that steer how text is displayed: control characters (C0, DEL
/// and C1), line and paragraph separators, and the format characters of Unicode (bidirectional
/// controls and isolates, zero-width characters, soft hyphen, word joiners, byte order mark, tags).
pub fn is_invisible_or_control(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{ad}'
                | '\u{600}'..='\u{605}'
                | '\u{61c}'
                | '\u{6dd}'
                | '\u{70f}'
                | '\u{8e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
        )
}

/// Replaces control characters, line separators and bidirectional or zero-width marks by a
/// visible `\u{..}` escape and cuts the text to `max_chars` characters (marking the cut).
pub fn escape_control(text: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max_chars.saturating_mul(2)));
    for (count, c) in text.chars().enumerate() {
        if count >= max_chars {
            out.push_str("[...]");
            break;
        }
        if is_invisible_or_control(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// The text cut to at most `max_chars` characters.
pub fn truncate_chars(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

const SECRET_PREFIXES: [&str; 14] = [
    "sk-",
    "sk_",
    "rk_",
    "pk_",
    "whsec_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "xox",
    "npm_",
    "mrg_",
];

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+' | '/')
}

fn looks_secret(token: &str) -> bool {
    let len = token.len();
    if len >= 16 && SECRET_PREFIXES.iter().any(|p| token.starts_with(p)) {
        return true;
    }
    if len == 20 && (token.starts_with("AKIA") || token.starts_with("ASIA")) {
        return token
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    }
    if len >= 20 && token.starts_with("eyJ") && token.matches('.').count() == 2 {
        return true;
    }
    if len >= 39 && token.starts_with("AIza") {
        return true;
    }
    len >= 32
        && token.bytes().any(|b| b.is_ascii_digit())
        && token.bytes().any(|b| b.is_ascii_alphabetic())
}

/// Replaces credential-shaped tokens in free text by `[redacted]`. A token that follows the word
/// `Bearer` or `Basic` is replaced whatever it looks like.
pub fn redact_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    let mut previous_word = String::new();
    let flush = |out: &mut String, token: &mut String, previous_word: &mut String| {
        if token.is_empty() {
            return;
        }
        let after_scheme = previous_word.eq_ignore_ascii_case("bearer")
            || previous_word.eq_ignore_ascii_case("basic");
        if after_scheme || looks_secret(token) {
            out.push_str(REDACTED);
        } else {
            out.push_str(token);
        }
        previous_word.clear();
        previous_word.push_str(token);
        token.clear();
    };
    for c in text.chars() {
        if is_token_char(c) {
            token.push(c);
        } else {
            flush(&mut out, &mut token, &mut previous_word);
            out.push(c);
            if !c.is_whitespace() {
                previous_word.clear();
            }
        }
    }
    flush(&mut out, &mut token, &mut previous_word);
    out
}

const SENSITIVE_KEYS: [&str; 11] = [
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "api-key",
    "private_key",
    "cookie",
    "credential",
];

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEYS.iter().any(|k| lower.contains(k))
}

/// A copy of `value` with the values of sensitive keys replaced and credential-shaped tokens in
/// strings redacted.
pub fn redact_value(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(redact_text(s)),
        Value::Array(items) => Value::Array(items.iter().map(redact_value).collect()),
        Value::Object(members) => Value::Object(
            members
                .iter()
                .map(|(k, v)| {
                    let v = if is_sensitive_key(k) && !v.is_null() {
                        Value::str(REDACTED)
                    } else {
                        redact_value(v)
                    };
                    (redact_text(k), v)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;
    use crate::json::parse;

    /// A credential-shaped string built at run time, so that no key-shaped literal is committed.
    fn shaped(prefix: &str, body_len: usize) -> String {
        let body: String = "aB3dE5gH7jK9mN1pQ".chars().cycle().take(body_len).collect();
        format!("{prefix}{body}")
    }

    #[test]
    fn control_characters_are_made_visible() {
        assert_eq!(escape_control("a\nb\tc", 100), "a\\u{a}b\\u{9}c");
        assert_eq!(
            escape_control("\u{1b}[31mred\u{1b}[0m", 100),
            "\\u{1b}[31mred\\u{1b}[0m"
        );
        assert_eq!(
            escape_control("x\u{7f}\u{85}\u{2028}\u{202e}\u{200b}\u{feff}", 100),
            "x\\u{7f}\\u{85}\\u{2028}\\u{202e}\\u{200b}\\u{feff}"
        );
        assert_eq!(escape_control("héllo ✓ 😀", 100), "héllo ✓ 😀");
        assert_eq!(escape_control("", 5), "");
    }

    #[test]
    fn escaped_text_has_no_control_characters_for_any_scalar_below_0x3000() {
        let all: String = (0..0x3000u32).filter_map(char::from_u32).collect();
        let escaped = escape_control(&all, usize::MAX);
        assert!(!escaped.chars().any(is_invisible_or_control));
    }

    #[test]
    fn long_text_is_cut_and_marked() {
        assert_eq!(escape_control("abcdef", 3), "abc[...]");
        assert_eq!(escape_control("abc", 3), "abc");
        assert_eq!(escape_control("a\nbcd", 2), "a\\u{a}[...]");
        assert_eq!(truncate_chars("héllo", 2), "hé");
    }

    #[test]
    fn credential_shaped_tokens_are_redacted() {
        for prefix in [
            "sk-",
            "sk_live_",
            "ghp_",
            "github_pat_",
            "whsec_",
            "xoxb-",
            "npm_",
            "mrg_",
        ] {
            let secret = shaped(prefix, 30);
            let text = format!("key {secret} end");
            assert_eq!(redact_text(&text), "key [redacted] end", "{prefix}");
        }
        let aws = format!("{}{}", "AKIA", "ABCDEFGHIJKLMNOP");
        assert_eq!(redact_text(&format!("id={aws};")), "id=[redacted];");
        let jwt = format!(
            "{}.{}.{}",
            shaped("eyJ", 20),
            shaped("eyJ", 20),
            shaped("", 20)
        );
        assert_eq!(redact_text(&jwt), "[redacted]");
        let long = shaped("", 40);
        assert_eq!(redact_text(&long), "[redacted]");
    }

    #[test]
    fn ordinary_text_is_left_alone() {
        for text in [
            "send hello to Alice at 5pm",
            "https://example.com/path?q=1",
            "sk-short",
            "AKIA-not-a-key",
            "abcdefghijklmnopqrstuvwxyzabcdefghij",
            "2026-11-04T12:00:00Z",
            "",
        ] {
            assert_eq!(redact_text(text), text);
        }
    }

    #[test]
    fn the_token_after_bearer_is_redacted_whatever_it_looks_like() {
        assert_eq!(
            redact_text("Authorization: Bearer abc123"),
            "Authorization: Bearer [redacted]"
        );
        assert_eq!(redact_text("bearer   short"), "bearer   [redacted]");
        assert_eq!(redact_text("Basic dXNlcg=="), "Basic [redacted]==");
        assert_eq!(redact_text("the bearer, x"), "the bearer, x");
    }

    #[test]
    fn values_are_redacted_by_key_and_by_shape() {
        let secret = shaped("sk-", 30);
        let v = parse(&format!(
            r#"{{"to":"Alice","password":"hunter2","nested":{{"API_KEY":"x","note":"use {secret} now","n":1}},"list":["{secret}","ok"],"token":null}}"#
        ))
        .unwrap();
        let r = redact_value(&v).to_json();
        assert!(!r.contains("hunter2") && !r.contains(&secret), "{r}");
        assert!(
            r.contains("\"to\":\"Alice\"") && r.contains("\"n\":1") && r.contains("\"token\":null")
        );
        assert!(
            r.contains("\"password\":\"[redacted]\"") && r.contains("\"API_KEY\":\"[redacted]\"")
        );
        assert!(r.contains("use [redacted] now"));
    }

    #[test]
    fn keys_that_look_like_credentials_are_redacted_too() {
        let secret = shaped("ghp_", 36);
        let v = Value::Object(vec![(secret.clone(), Value::int(1))]);
        assert!(!redact_value(&v).to_json().contains(&secret));
    }
}
