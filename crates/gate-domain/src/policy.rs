//! Which tools a caller may see and call, and what their arguments may contain.
//!
//! The rule is default-deny. A tool passes when it is on the allowlist, is not on the denylist
//! and, with the `read_only` preset on, also matches one of the read patterns. The denylist
//! always wins. A token may carry a narrower list of its own, which can only remove tools.

use crate::auth::TokenEntry;
use crate::glob::Glob;
use crate::json::Value;

/// Name patterns of tools that read and do not change anything, used by the `read_only` preset.
pub const DEFAULT_READ_PATTERNS: [&str; 10] = [
    "get_*",
    "list_*",
    "read_*",
    "search_*",
    "find_*",
    "describe_*",
    "show_*",
    "view_*",
    "count_*",
    "lookup_*",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The tool is not on the allowlist (the default).
    NotAllowed,
    /// The tool matches a denylist pattern.
    Denied,
    /// The read-only preset is on and the name does not look like a read.
    NotReadOnly,
    /// The calling token is limited to other tools.
    TokenLimited,
}

impl DenyReason {
    /// A short stable code for the audit log.
    pub fn code(&self) -> &'static str {
        match self {
            DenyReason::NotAllowed => "not_in_allowlist",
            DenyReason::Denied => "denylist",
            DenyReason::NotReadOnly => "read_only",
            DenyReason::TokenLimited => "token_tools",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// Limits for the arguments of the tools whose name matches `tool`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgRule {
    pub tool: Glob,
    /// Largest serialized size of the `arguments` object.
    pub max_arg_bytes: Option<usize>,
    /// Longest string value or object key, in characters.
    pub max_string_len: Option<usize>,
    /// String values (and keys) that match one of these patterns are refused.
    pub forbid_values: Vec<Glob>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgViolation {
    TooLarge,
    StringTooLong,
    ForbiddenValue,
}

impl ArgViolation {
    pub fn code(&self) -> &'static str {
        match self {
            ArgViolation::TooLarge => "arguments_too_large",
            ArgViolation::StringTooLong => "argument_string_too_long",
            ArgViolation::ForbiddenValue => "argument_forbidden",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ToolPolicy {
    pub allow: Vec<Glob>,
    pub deny: Vec<Glob>,
    pub read_only: bool,
    pub read_patterns: Vec<Glob>,
    pub rules: Vec<ArgRule>,
}

fn any_match(patterns: &[Glob], name: &str) -> bool {
    patterns.iter().any(|g| g.matches(name))
}

impl ToolPolicy {
    pub fn decide(&self, tool: &str) -> Decision {
        if any_match(&self.deny, tool) {
            return Decision::Deny(DenyReason::Denied);
        }
        let listed = if self.allow.is_empty() {
            self.read_only
        } else {
            any_match(&self.allow, tool)
        };
        if !listed {
            return Decision::Deny(DenyReason::NotAllowed);
        }
        if self.read_only && !any_match(&self.read_patterns, tool) {
            return Decision::Deny(DenyReason::NotReadOnly);
        }
        Decision::Allow
    }

    /// The decision for a call made with `token`: the global policy first, then the token's own
    /// narrower list.
    pub fn decide_for(&self, token: &TokenEntry, tool: &str) -> Decision {
        match self.decide(tool) {
            Decision::Allow if !token.permits_tool(tool) => {
                Decision::Deny(DenyReason::TokenLimited)
            }
            other => other,
        }
    }

    /// Checks the arguments of a `tools/call` against the rules that apply to `tool`.
    pub fn check_arguments(
        &self,
        tool: &str,
        arguments: Option<&Value>,
    ) -> Result<(), ArgViolation> {
        let Some(arguments) = arguments else {
            return Ok(());
        };
        for rule in self.rules.iter().filter(|r| r.tool.matches(tool)) {
            if let Some(max) = rule.max_arg_bytes {
                if arguments.to_json().len() > max {
                    return Err(ArgViolation::TooLarge);
                }
            }
            check_value(rule, arguments)?;
        }
        Ok(())
    }
}

fn check_text(rule: &ArgRule, text: &str) -> Result<(), ArgViolation> {
    if let Some(max) = rule.max_string_len {
        if text.chars().count() > max {
            return Err(ArgViolation::StringTooLong);
        }
    }
    if rule.forbid_values.iter().any(|g| g.matches(text)) {
        return Err(ArgViolation::ForbiddenValue);
    }
    Ok(())
}

fn check_value(rule: &ArgRule, value: &Value) -> Result<(), ArgViolation> {
    match value {
        Value::String(s) => check_text(rule, s),
        Value::Array(items) => items.iter().try_for_each(|v| check_value(rule, v)),
        Value::Object(members) => members.iter().try_for_each(|(k, v)| {
            check_text(rule, k)?;
            check_value(rule, v)
        }),
        _ => Ok(()),
    }
}

/// Parses a list of patterns, naming the first one that is invalid.
pub fn parse_globs(patterns: &[&str]) -> Result<Vec<Glob>, (usize, crate::glob::GlobError)> {
    patterns
        .iter()
        .enumerate()
        .map(|(i, p)| Glob::new(p).map_err(|e| (i, e)))
        .collect()
}

pub fn default_read_patterns() -> Vec<Glob> {
    DEFAULT_READ_PATTERNS
        .iter()
        .filter_map(|p| Glob::new(p).ok())
        .collect()
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
    use crate::auth::{Scope, TokenHash, TokenId};
    use crate::json::parse;

    fn globs(patterns: &[&str]) -> Vec<Glob> {
        parse_globs(patterns).unwrap()
    }

    fn policy(allow: &[&str], deny: &[&str], read_only: bool) -> ToolPolicy {
        ToolPolicy {
            allow: globs(allow),
            deny: globs(deny),
            read_only,
            read_patterns: default_read_patterns(),
            rules: vec![],
        }
    }

    fn token(tools: Option<&[&str]>) -> TokenEntry {
        TokenEntry {
            id: TokenId::new("t").unwrap(),
            hash: TokenHash::of_token("x"),
            scopes: vec![Scope::ToolsList, Scope::ToolsCall],
            tools: tools.map(globs),
        }
    }

    #[test]
    fn default_policy_denies_everything() {
        let p = ToolPolicy::default();
        for tool in ["get_chats", "send_message", "", "anything"] {
            assert_eq!(p.decide(tool), Decision::Deny(DenyReason::NotAllowed));
        }
    }

    #[test]
    fn allowlist_and_denylist() {
        let p = policy(&["*"], &["send_*", "delete_*"], false);
        assert_eq!(p.decide("get_chats"), Decision::Allow);
        assert_eq!(p.decide("send_message"), Decision::Deny(DenyReason::Denied));
        assert_eq!(p.decide("delete_all"), Decision::Deny(DenyReason::Denied));
        let p = policy(&["get_chats", "send_message"], &["send_message"], false);
        assert_eq!(
            p.decide("send_message"),
            Decision::Deny(DenyReason::Denied),
            "deny beats allow"
        );
        assert_eq!(p.decide("get_chats"), Decision::Allow);
        assert_eq!(
            p.decide("get_other"),
            Decision::Deny(DenyReason::NotAllowed)
        );
    }

    #[test]
    fn read_only_preset() {
        let p = policy(&[], &[], true);
        assert_eq!(p.decide("list_chats"), Decision::Allow);
        assert_eq!(p.decide("search_messages"), Decision::Allow);
        assert_eq!(
            p.decide("send_message"),
            Decision::Deny(DenyReason::NotReadOnly)
        );
        assert_eq!(
            p.decide("unknown_tool"),
            Decision::Deny(DenyReason::NotReadOnly)
        );
        let p = policy(&["*"], &[], true);
        assert_eq!(p.decide("get_x"), Decision::Allow);
        assert_eq!(p.decide("send_x"), Decision::Deny(DenyReason::NotReadOnly));
        let p = policy(&["get_chats", "send_message"], &[], true);
        assert_eq!(p.decide("get_chats"), Decision::Allow);
        assert_eq!(
            p.decide("send_message"),
            Decision::Deny(DenyReason::NotReadOnly)
        );
        assert_eq!(
            p.decide("list_chats"),
            Decision::Deny(DenyReason::NotAllowed),
            "allow narrows the read set"
        );
        let p = policy(&[], &["get_secret"], true);
        assert_eq!(p.decide("get_secret"), Decision::Deny(DenyReason::Denied));
    }

    #[test]
    fn names_that_can_run_arbitrary_work_are_not_reads_by_default() {
        // a tool named query_sql or fetch_and_post may write or send; the operator can add them
        let p = policy(&[], &[], true);
        for tool in [
            "query_sql",
            "fetch_and_post",
            "fetch_url",
            "query_database",
            "get_or_create_chat",
        ] {
            let expected = if tool.starts_with("get_") {
                Decision::Allow
            } else {
                Decision::Deny(DenyReason::NotReadOnly)
            };
            assert_eq!(p.decide(tool), expected, "{tool}");
        }
        let mut wider = policy(&[], &[], true);
        wider.read_patterns = globs(&["get_*", "query_*"]);
        assert_eq!(
            wider.decide("query_sql"),
            Decision::Allow,
            "the operator can widen the preset"
        );
    }

    #[test]
    fn turning_read_only_off_is_the_switch() {
        assert_eq!(
            policy(&["*"], &[], true).decide("send_message"),
            Decision::Deny(DenyReason::NotReadOnly)
        );
        assert_eq!(
            policy(&["*"], &[], false).decide("send_message"),
            Decision::Allow
        );
    }

    #[test]
    fn token_lists_only_narrow() {
        let p = policy(&["get_*", "send_*"], &["send_*"], false);
        assert_eq!(p.decide_for(&token(None), "get_a"), Decision::Allow);
        assert_eq!(
            p.decide_for(&token(Some(&["get_a"])), "get_a"),
            Decision::Allow
        );
        assert_eq!(
            p.decide_for(&token(Some(&["get_a"])), "get_b"),
            Decision::Deny(DenyReason::TokenLimited)
        );
        // a token list never widens: the global denylist still wins
        assert_eq!(
            p.decide_for(&token(Some(&["send_*"])), "send_x"),
            Decision::Deny(DenyReason::Denied)
        );
        assert_eq!(
            p.decide_for(&token(Some(&["*"])), "other"),
            Decision::Deny(DenyReason::NotAllowed)
        );
        assert!(Decision::Allow.is_allowed() && !Decision::Deny(DenyReason::Denied).is_allowed());
    }

    /// A tiny deterministic generator keeps the property tests free of dependencies.
    fn rng(seed: u64) -> impl FnMut() -> u64 {
        let mut x = seed;
        move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        }
    }

    fn random_name(next: &mut dyn FnMut() -> u64) -> String {
        let parts = [
            "get", "send", "list", "delete", "_", "chat", "message", "x", "*", "?", "é",
        ];
        (0..1 + next() % 4)
            .map(|_| parts[(next() % parts.len() as u64) as usize])
            .collect()
    }

    fn random_pattern(next: &mut dyn FnMut() -> u64) -> Glob {
        loop {
            let mut text: String = random_name(next);
            if next().is_multiple_of(3) {
                text.push('*');
            }
            if let Ok(g) = Glob::new(&text) {
                return g;
            }
        }
    }

    #[test]
    fn property_deny_always_wins_and_the_default_denies() {
        let mut next = rng(0x5eed_1234_abcd_ef01);
        for _ in 0..3000 {
            let policy = ToolPolicy {
                allow: (0..next() % 3).map(|_| random_pattern(&mut next)).collect(),
                deny: (0..next() % 3).map(|_| random_pattern(&mut next)).collect(),
                read_only: next().is_multiple_of(2),
                read_patterns: default_read_patterns(),
                rules: vec![],
            };
            let tool = random_name(&mut next);
            let decision = policy.decide(&tool);
            if policy.deny.iter().any(|g| g.matches(&tool)) {
                assert_eq!(decision, Decision::Deny(DenyReason::Denied), "{tool}");
            }
            if decision.is_allowed() {
                assert!(!policy.deny.iter().any(|g| g.matches(&tool)));
                let listed = if policy.allow.is_empty() {
                    policy.read_only
                } else {
                    policy.allow.iter().any(|g| g.matches(&tool))
                };
                assert!(
                    listed,
                    "an allowed tool is on the allowlist (or the read preset): {tool}"
                );
                if policy.read_only {
                    assert!(
                        policy.read_patterns.iter().any(|g| g.matches(&tool)),
                        "read_only allows reads only: {tool}"
                    );
                }
            }
            if policy.allow.is_empty() && !policy.read_only {
                assert!(
                    !decision.is_allowed(),
                    "nothing is allowed by default: {tool}"
                );
            }
        }
    }

    #[test]
    fn property_a_token_list_never_widens_the_policy() {
        let mut next = rng(0x0bad_cafe_f00d_1111);
        for _ in 0..3000 {
            let policy = ToolPolicy {
                allow: (0..next() % 3).map(|_| random_pattern(&mut next)).collect(),
                deny: (0..next() % 2).map(|_| random_pattern(&mut next)).collect(),
                read_only: next().is_multiple_of(2),
                read_patterns: default_read_patterns(),
                rules: vec![],
            };
            let mut t = token(None);
            t.tools = Some((0..next() % 3).map(|_| random_pattern(&mut next)).collect());
            let tool = random_name(&mut next);
            if policy.decide_for(&t, &tool).is_allowed() {
                assert!(policy.decide(&tool).is_allowed(), "{tool}");
            }
        }
    }

    #[test]
    fn deny_reason_codes_are_distinct() {
        let codes = [
            DenyReason::NotAllowed,
            DenyReason::Denied,
            DenyReason::NotReadOnly,
            DenyReason::TokenLimited,
        ]
        .map(|r| r.code());
        for (i, a) in codes.iter().enumerate() {
            for b in &codes[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    fn rule(
        tool: &str,
        max_bytes: Option<usize>,
        max_str: Option<usize>,
        forbid: &[&str],
    ) -> ArgRule {
        ArgRule {
            tool: Glob::new(tool).unwrap(),
            max_arg_bytes: max_bytes,
            max_string_len: max_str,
            forbid_values: globs(forbid),
        }
    }

    #[test]
    fn argument_rules() {
        let mut p = policy(&["*"], &[], false);
        p.rules = vec![rule("send_*", Some(60), Some(10), &["*http://*", "+999*"])];
        let args = |t: &str| parse(t).unwrap();
        assert_eq!(
            p.check_arguments("send_message", Some(&args(r#"{"to":"abc","text":"hi"}"#))),
            Ok(())
        );
        assert_eq!(
            p.check_arguments(
                "get_x",
                Some(&args(&format!("{{\"a\":\"{}\"}}", "x".repeat(500))))
            ),
            Ok(()),
            "other tools are not limited"
        );
        assert_eq!(p.check_arguments("send_message", None), Ok(()));
        assert_eq!(
            p.check_arguments(
                "send_message",
                Some(&args(&format!("{{\"text\":\"{}\"}}", "x".repeat(80))))
            ),
            Err(ArgViolation::TooLarge)
        );
        assert_eq!(
            p.check_arguments("send_message", Some(&args(r#"{"text":"0123456789a"}"#))),
            Err(ArgViolation::StringTooLong)
        );
        assert_eq!(
            p.check_arguments("send_message", Some(&args(r#"{"text":"a http://x"}"#))),
            Err(ArgViolation::ForbiddenValue)
        );
        assert_eq!(
            p.check_arguments(
                "send_message",
                Some(&args(r#"{"to":["a",{"n":"+999123"}]}"#))
            ),
            Err(ArgViolation::ForbiddenValue)
        );
        assert_eq!(
            p.check_arguments("send_message", Some(&args(r#"{"+9991":1}"#))),
            Err(ArgViolation::ForbiddenValue),
            "keys are checked too"
        );
        assert_eq!(
            p.check_arguments("send_message", Some(&args(r#"{"é":"ééééééééé"}"#))),
            Ok(()),
            "length counts characters"
        );
    }

    #[test]
    fn several_rules_apply_together() {
        let p = ToolPolicy {
            rules: vec![
                rule("*", None, Some(5), &[]),
                rule("send_*", None, None, &["bad"]),
            ],
            ..ToolPolicy::default()
        };
        assert_eq!(
            p.check_arguments("send_x", Some(&parse(r#"{"a":"bad"}"#).unwrap())),
            Err(ArgViolation::ForbiddenValue)
        );
        assert_eq!(
            p.check_arguments("send_x", Some(&parse(r#"{"a":"toolong"}"#).unwrap())),
            Err(ArgViolation::StringTooLong)
        );
        assert_eq!(
            p.check_arguments("get_x", Some(&parse(r#"{"a":"bad"}"#).unwrap())),
            Ok(())
        );
        let codes = [
            ArgViolation::TooLarge,
            ArgViolation::StringTooLong,
            ArgViolation::ForbiddenValue,
        ]
        .map(|v| v.code());
        assert!(codes[0] != codes[1] && codes[1] != codes[2] && codes[0] != codes[2]);
    }

    #[test]
    fn glob_list_parsing_names_the_bad_entry() {
        assert_eq!(parse_globs(&["ok", "", "x"]).unwrap_err().0, 1);
        assert_eq!(default_read_patterns().len(), DEFAULT_READ_PATTERNS.len());
    }
}
