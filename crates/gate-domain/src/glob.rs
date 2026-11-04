//! Glob patterns for tool names: `*` matches any run of characters (also none), `?` matches
//! exactly one character, everything else matches itself. Matching is case-sensitive and runs
//! in time proportional to the product of the lengths (no exponential backtracking).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob {
    pattern: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobError {
    Empty,
    TooLong,
    ControlCharacter,
}

impl std::fmt::Display for GlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            GlobError::Empty => "the pattern is empty",
            GlobError::TooLong => "the pattern is longer than 128 characters",
            GlobError::ControlCharacter => "the pattern contains a control character",
        })
    }
}

pub const MAX_PATTERN_CHARS: usize = 128;

impl Glob {
    pub fn new(pattern: &str) -> Result<Glob, GlobError> {
        if pattern.is_empty() {
            return Err(GlobError::Empty);
        }
        if pattern.chars().count() > MAX_PATTERN_CHARS {
            return Err(GlobError::TooLong);
        }
        if pattern.chars().any(char::is_control) {
            return Err(GlobError::ControlCharacter);
        }
        Ok(Glob {
            pattern: pattern.to_string(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    pub fn matches(&self, text: &str) -> bool {
        matches(&self.pattern, text)
    }

    /// Whether the pattern contains no wildcard.
    pub fn is_literal(&self) -> bool {
        !self.pattern.contains(['*', '?'])
    }
}

/// The first character of `s` at byte offset `at`, with its length in bytes.
fn char_at(s: &str, at: usize) -> Option<(char, usize)> {
    s.get(at..)
        .and_then(|rest| rest.chars().next())
        .map(|c| (c, c.len_utf8()))
}

pub fn matches(pattern: &str, text: &str) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    // where to resume after the most recent `*`: (pattern offset after the star, text offset)
    let mut star: Option<(usize, usize)> = None;
    loop {
        let pc = char_at(pattern, p);
        let tc = char_at(text, t);
        match (pc, tc) {
            (Some(('*', n)), _) => {
                p += n;
                star = Some((p, t));
            }
            (Some(('?', n)), Some((_, m))) => {
                p += n;
                t += m;
            }
            (Some((a, n)), Some((b, m))) if a == b => {
                p += n;
                t += m;
            }
            (None, None) => return true,
            _ => {
                // mismatch: let the last star swallow one more character, or fail
                let Some((sp, st)) = star else { return false };
                let Some((_, m)) = char_at(text, st) else {
                    return false;
                };
                star = Some((sp, st + m));
                p = sp;
                t = st + m;
            }
        }
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

    #[test]
    fn literals_and_wildcards() {
        assert!(matches("send_message", "send_message"));
        assert!(!matches("send_message", "send_messages"));
        assert!(!matches("send_message", "send_messag"));
        assert!(matches("*", ""));
        assert!(matches("*", "anything at all"));
        assert!(matches("send_*", "send_"));
        assert!(matches("send_*", "send_message"));
        assert!(!matches("send_*", "resend_message"));
        assert!(matches("*_message", "send_message"));
        assert!(matches("*message*", "x_message_y"));
        assert!(matches("a*b*c", "aXXbYYc"));
        assert!(matches("a*b*c", "abc"));
        assert!(!matches("a*b*c", "aXXbYY"));
        assert!(matches("?", "x"));
        assert!(!matches("?", ""));
        assert!(!matches("?", "xy"));
        assert!(matches("get_?", "get_1"));
        assert!(matches("**", "x"));
        assert!(matches("a**b", "ab"));
    }

    #[test]
    fn matching_is_case_sensitive_and_unicode_aware() {
        assert!(!matches("Send_*", "send_x"));
        assert!(matches("caf?", "café"));
        assert!(matches("*é", "café"));
        assert!(matches("?", "😀"));
        assert!(!matches("??", "😀"));
    }

    #[test]
    fn backtracking_cases() {
        assert!(matches("*ab*ab*", "xxabxxab"));
        assert!(matches("*aab", "aaab"));
        assert!(!matches("*aab", "aaba"));
        assert!(matches("a*a*a*a", "aaaa"));
        assert!(!matches("a*a*a*a", "aaa"));
    }

    #[test]
    fn pathological_patterns_stay_fast() {
        let pattern = format!("{}b", "a*".repeat(40));
        let text = "a".repeat(5000);
        assert!(!matches(&pattern, &text));
    }

    #[test]
    fn a_pattern_without_wildcards_equals_string_equality() {
        let samples = ["", "a", "ab", "send", "send_message", "é", "a b"];
        for p in samples {
            for t in samples {
                assert_eq!(matches(p, t), p == t, "{p:?} {t:?}");
            }
        }
    }

    #[test]
    fn validation() {
        assert_eq!(Glob::new(""), Err(GlobError::Empty));
        assert_eq!(Glob::new(&"a".repeat(129)), Err(GlobError::TooLong));
        assert_eq!(Glob::new("a\nb"), Err(GlobError::ControlCharacter));
        assert!(Glob::new(&"a".repeat(128)).is_ok());
        let g = Glob::new("send_*").unwrap();
        assert_eq!(g.as_str(), "send_*");
        assert!(g.matches("send_x") && !g.is_literal());
        assert!(Glob::new("ping").unwrap().is_literal());
        assert!(
            !GlobError::Empty.to_string().is_empty() && !GlobError::TooLong.to_string().is_empty()
        );
        assert!(!GlobError::ControlCharacter.to_string().is_empty());
    }
}
