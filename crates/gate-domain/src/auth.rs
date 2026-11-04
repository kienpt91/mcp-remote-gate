//! Bearer tokens: how they are made, stored, parsed from a header and checked.
//!
//! A token is `mrg_` followed by the base64url text of 32 random bytes. The configuration stores
//! only its SHA-256 (`sha256:<hex>`), so a leaked config file does not leak a credential. The
//! tokens carry 256 bits of entropy, which is why a plain digest (no salt, no stretching) is
//! enough: there is nothing to guess.

use crate::glob::Glob;
use crate::hash::{base64url_encode, ct_eq, hex_decode_array, hex_encode, sha256};

pub const TOKEN_PREFIX: &str = "mrg_";
pub const TOKEN_ENTROPY_BYTES: usize = 32;
/// Longest Authorization credential the gateway looks at.
pub const MAX_TOKEN_LEN: usize = 256;

/// The text of a new token for 32 bytes of entropy supplied by the caller.
pub fn token_from_entropy(entropy: &[u8; TOKEN_ENTROPY_BYTES]) -> String {
    format!("{TOKEN_PREFIX}{}", base64url_encode(entropy))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenHash([u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadHash;

impl TokenHash {
    pub fn of_token(token: &str) -> TokenHash {
        TokenHash(sha256(token.as_bytes()))
    }

    /// Parses `sha256:<64 hex digits>`.
    pub fn parse(text: &str) -> Result<TokenHash, BadHash> {
        let digits = text.strip_prefix("sha256:").ok_or(BadHash)?;
        hex_decode_array::<32>(digits).map(TokenHash).ok_or(BadHash)
    }

    pub fn to_config_string(&self) -> String {
        format!("sha256:{}", hex_encode(&self.0))
    }

    pub fn matches(&self, other: &TokenHash) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

/// A token name for the audit log: 1 to 64 characters of `[A-Za-z0-9_.-]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenId(String);

impl TokenId {
    pub fn new(id: &str) -> Option<TokenId> {
        let ok = !id.is_empty()
            && id.len() <= 64
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
        ok.then(|| TokenId(id.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    ToolsList,
    ToolsCall,
}

impl Scope {
    pub fn parse(text: &str) -> Option<Scope> {
        match text {
            "tools:list" => Some(Scope::ToolsList),
            "tools:call" => Some(Scope::ToolsCall),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::ToolsList => "tools:list",
            Scope::ToolsCall => "tools:call",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenEntry {
    pub id: TokenId,
    pub hash: TokenHash,
    pub scopes: Vec<Scope>,
    /// When set, this token sees and calls only tools that also match one of these patterns.
    /// It can narrow the global tool policy, never widen it.
    pub tools: Option<Vec<Glob>>,
}

impl TokenEntry {
    pub fn has_scope(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    pub fn permits_tool(&self, name: &str) -> bool {
        self.tools
            .as_ref()
            .is_none_or(|patterns| patterns.iter().any(|g| g.matches(name)))
    }
}

#[derive(Debug, Default)]
pub struct Authenticator {
    tokens: Vec<TokenEntry>,
}

impl Authenticator {
    pub fn new(tokens: Vec<TokenEntry>) -> Authenticator {
        Authenticator { tokens }
    }

    pub fn tokens(&self) -> &[TokenEntry] {
        &self.tokens
    }

    /// The entry whose hash matches `presented`. Every configured hash is compared, in constant
    /// time per comparison and without stopping at the first match, so the time does not tell
    /// which token (if any) was close.
    pub fn authenticate(&self, presented: &str) -> Option<&TokenEntry> {
        let digest = TokenHash::of_token(presented);
        let mut found: Option<&TokenEntry> = None;
        for entry in &self.tokens {
            if entry.hash.matches(&digest) {
                found = Some(entry);
            }
        }
        found
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerError {
    /// No Authorization header, or another scheme than Bearer.
    Missing,
    /// A Bearer credential that is empty, too long or has characters no token has.
    Malformed,
}

/// Extracts the credential from an `Authorization` header value.
pub fn bearer_token(header: Option<&str>) -> Result<&str, BearerError> {
    let value = header.ok_or(BearerError::Missing)?;
    let (scheme, rest) = value.split_once(' ').ok_or(BearerError::Missing)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(BearerError::Missing);
    }
    let token = rest.trim_matches(' ');
    let charset_ok = token.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'+' | b'/' | b'=')
    });
    if token.is_empty() || token.len() > MAX_TOKEN_LEN || !charset_ok {
        return Err(BearerError::Malformed);
    }
    Ok(token)
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

    fn entry(id: &str, token: &str) -> TokenEntry {
        TokenEntry {
            id: TokenId::new(id).unwrap(),
            hash: TokenHash::of_token(token),
            scopes: vec![Scope::ToolsList, Scope::ToolsCall],
            tools: None,
        }
    }

    fn make_token(seed: u8) -> String {
        token_from_entropy(&[seed; 32])
    }

    #[test]
    fn tokens_have_a_fixed_shape() {
        let t = make_token(7);
        assert!(t.starts_with("mrg_"));
        assert_eq!(t.len(), 4 + 43);
        assert_ne!(make_token(1), make_token(2));
    }

    #[test]
    fn hash_roundtrip_and_parse_errors() {
        let h = TokenHash::of_token("x");
        let text = h.to_config_string();
        assert!(text.starts_with("sha256:") && text.len() == 7 + 64);
        assert_eq!(TokenHash::parse(&text), Ok(h));
        assert_eq!(
            TokenHash::parse(&text.to_uppercase().replace("SHA256", "sha256")),
            Ok(h)
        );
        for bad in [
            "",
            "sha256:",
            "sha1:00",
            &text[7..],
            &format!("{text}0"),
            &text[..text.len() - 1],
            "sha256:zz",
        ] {
            assert_eq!(TokenHash::parse(bad), Err(BadHash), "{bad}");
        }
    }

    #[test]
    fn authenticates_the_matching_token_only() {
        let (a, b) = (make_token(1), make_token(2));
        let auth = Authenticator::new(vec![entry("alpha", &a), entry("beta", &b)]);
        assert_eq!(auth.authenticate(&a).map(|e| e.id.as_str()), Some("alpha"));
        assert_eq!(auth.authenticate(&b).map(|e| e.id.as_str()), Some("beta"));
        assert!(auth.authenticate(&make_token(3)).is_none());
        assert!(auth.authenticate("").is_none());
        assert!(auth.authenticate(&format!("{a}x")).is_none());
        assert!(auth.authenticate(&a[..a.len() - 1]).is_none());
        assert!(Authenticator::default().authenticate(&a).is_none());
        assert_eq!(auth.tokens().len(), 2);
    }

    #[test]
    fn a_token_never_matches_when_only_a_prefix_or_the_hash_is_presented() {
        let a = make_token(1);
        let auth = Authenticator::new(vec![entry("alpha", &a)]);
        let hash_text = TokenHash::of_token(&a).to_config_string();
        assert!(auth.authenticate(&hash_text).is_none());
        assert!(auth.authenticate(&hash_text[7..]).is_none());
        assert!(auth.authenticate(&a[..10]).is_none());
    }

    #[test]
    fn token_ids() {
        assert!(TokenId::new("desktop-1.a_b").is_some());
        for bad in ["", "a b", "a/b", "é", "a\n", &"x".repeat(65)] {
            assert!(TokenId::new(bad).is_none(), "{bad:?}");
        }
        assert!(TokenId::new(&"x".repeat(64)).is_some());
    }

    #[test]
    fn scopes_and_tool_narrowing() {
        for s in [Scope::ToolsList, Scope::ToolsCall] {
            assert_eq!(Scope::parse(s.as_str()), Some(s));
        }
        assert_eq!(Scope::parse("tools"), None);
        let mut e = entry("a", "t");
        e.scopes = vec![Scope::ToolsList];
        assert!(e.has_scope(Scope::ToolsList) && !e.has_scope(Scope::ToolsCall));
        assert!(e.permits_tool("anything"));
        e.tools = Some(vec![
            Glob::new("search_*").unwrap(),
            Glob::new("ping").unwrap(),
        ]);
        assert!(e.permits_tool("search_x") && e.permits_tool("ping"));
        assert!(!e.permits_tool("send_x"));
        e.tools = Some(vec![]);
        assert!(!e.permits_tool("ping"));
    }

    #[test]
    fn bearer_header_parsing() {
        let t = make_token(9);
        assert_eq!(bearer_token(Some(&format!("Bearer {t}"))), Ok(t.as_str()));
        assert_eq!(bearer_token(Some(&format!("bearer {t}"))), Ok(t.as_str()));
        assert_eq!(bearer_token(Some(&format!("BEARER  {t} "))), Ok(t.as_str()));
        assert_eq!(bearer_token(None), Err(BearerError::Missing));
        assert_eq!(bearer_token(Some("Basic abc")), Err(BearerError::Missing));
        assert_eq!(bearer_token(Some("Bearer")), Err(BearerError::Missing));
        assert_eq!(bearer_token(Some(&t)), Err(BearerError::Missing));
        assert_eq!(bearer_token(Some("Bearer ")), Err(BearerError::Malformed));
        assert_eq!(
            bearer_token(Some("Bearer a b")),
            Err(BearerError::Malformed)
        );
        assert_eq!(
            bearer_token(Some("Bearer a\u{0}b")),
            Err(BearerError::Malformed)
        );
        assert_eq!(bearer_token(Some("Bearer é")), Err(BearerError::Malformed));
        assert_eq!(
            bearer_token(Some(&format!("Bearer {}", "a".repeat(MAX_TOKEN_LEN + 1)))),
            Err(BearerError::Malformed)
        );
        assert!(bearer_token(Some(&format!("Bearer {}", "a".repeat(MAX_TOKEN_LEN)))).is_ok());
    }
}
