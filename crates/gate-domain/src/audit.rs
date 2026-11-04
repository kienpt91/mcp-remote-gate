//! The audit record: one JSON line per request, never carrying a token or (by default) the
//! values of the arguments.

use crate::json::Value;
use crate::sanitize::escape_control;

/// Longest text of a client-supplied field (method, tool, peer) kept in a record.
pub const MAX_FIELD_CHARS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The request was served.
    Allowed,
    /// The gateway refused it.
    Denied,
    /// It was allowed but failed (upstream error, timeout, oversized result).
    Error,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Allowed => "allowed",
            Outcome::Denied => "denied",
            Outcome::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuditRecord {
    pub unix_ms: u64,
    /// The configured id of the token, `None` when the request was not authenticated.
    pub token: Option<String>,
    /// The peer IP address, without the port.
    pub peer: Option<String>,
    pub method: String,
    pub tool: Option<String>,
    pub outcome: Outcome,
    /// A stable short code: `ok`, `not_in_allowlist`, `bad_token`, ...
    pub reason: String,
    pub duration_ms: u64,
    pub request_bytes: usize,
    pub response_bytes: usize,
    /// The redacted arguments, only when the operator turned argument logging on.
    pub arguments: Option<String>,
    /// How many unauthenticated records were dropped since the previous one.
    pub suppressed: u64,
}

impl AuditRecord {
    /// The record as one line of JSON (no trailing newline).
    pub fn to_line(&self) -> String {
        // every client- or server-supplied text goes through the same escaping as the log lines on stderr
        let text = |s: &str| Value::String(escape_control(s, MAX_FIELD_CHARS));
        let opt = |s: &Option<String>| s.as_deref().map_or(Value::Null, text);
        let mut members: Vec<(String, Value)> = vec![
            ("v".into(), Value::int(1)),
            ("ts".into(), Value::String(rfc3339_millis(self.unix_ms))),
            ("token".into(), opt(&self.token)),
            ("peer".into(), opt(&self.peer)),
            ("method".into(), text(&self.method)),
            ("tool".into(), opt(&self.tool)),
            ("outcome".into(), Value::str(self.outcome.as_str())),
            ("reason".into(), text(&self.reason)),
            ("duration_ms".into(), Value::uint(self.duration_ms)),
            (
                "request_bytes".into(),
                Value::uint(self.request_bytes as u64),
            ),
            (
                "response_bytes".into(),
                Value::uint(self.response_bytes as u64),
            ),
        ];
        if let Some(arguments) = &self.arguments {
            members.push(("arguments".into(), Value::str(arguments)));
        }
        if self.suppressed > 0 {
            members.push(("suppressed".into(), Value::uint(self.suppressed)));
        }
        Value::Object(members).to_json()
    }
}

/// `unix_ms` as `YYYY-MM-DDTHH:MM:SS.mmmZ` (UTC).
pub fn rfc3339_millis(unix_ms: u64) -> String {
    let millis = unix_ms % 1000;
    let secs = unix_ms / 1000;
    let (days, secs_of_day) = (secs / 86_400, secs % 86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        secs_of_day / 3600,
        secs_of_day % 3600 / 60,
        secs_of_day % 60
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian (Howard Hinnant's algorithm).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
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

    fn record() -> AuditRecord {
        AuditRecord {
            unix_ms: 1_730_000_000_123,
            token: Some("desktop".into()),
            peer: Some("127.0.0.1".into()),
            method: "tools/call".into(),
            tool: Some("send_message".into()),
            outcome: Outcome::Denied,
            reason: "denylist".into(),
            duration_ms: 3,
            request_bytes: 120,
            response_bytes: 88,
            arguments: None,
            suppressed: 0,
        }
    }

    #[test]
    fn known_timestamps() {
        assert_eq!(rfc3339_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_millis(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(
            rfc3339_millis(1_730_000_000_123),
            "2024-10-27T03:33:20.123Z"
        );
        assert_eq!(
            rfc3339_millis(1_782_864_000_999),
            "2026-07-01T00:00:00.999Z"
        );
        assert_eq!(
            rfc3339_millis(4_102_444_799_000),
            "2099-12-31T23:59:59.000Z"
        );
        assert_eq!(
            rfc3339_millis(4_107_542_400_000),
            "2100-03-01T00:00:00.000Z"
        );
    }

    #[test]
    fn the_line_has_the_documented_fields() {
        let line = record().to_line();
        assert_eq!(
            line,
            r#"{"v":1,"ts":"2024-10-27T03:33:20.123Z","token":"desktop","peer":"127.0.0.1","method":"tools/call","tool":"send_message","outcome":"denied","reason":"denylist","duration_ms":3,"request_bytes":120,"response_bytes":88}"#
        );
        assert!(!line.contains('\n'));
    }

    #[test]
    fn optional_fields() {
        let mut r = record();
        r.token = None;
        r.peer = None;
        r.tool = None;
        r.arguments = Some("{\"to\":\"x\"}".into());
        r.suppressed = 4;
        let v = parse(&r.to_line()).unwrap();
        assert!(v.get("token").unwrap().is_null() && v.get("tool").unwrap().is_null());
        assert_eq!(
            v.get("arguments").and_then(Value::as_str),
            Some("{\"to\":\"x\"}")
        );
        assert_eq!(v.get("suppressed").and_then(Value::as_u64), Some(4));
    }

    #[test]
    fn hostile_fields_cannot_break_the_line_or_grow_it() {
        let mut r = record();
        r.method = "a\nb\"{\"forged\":1}\u{1b}[2J".into();
        r.tool = Some("x".repeat(100_000));
        let line = r.to_line();
        assert!(!line.contains('\n') && !line.contains('\u{1b}'));
        assert!(line.len() < 1000);
        let v = parse(&line).unwrap();
        assert!(v.get("forged").is_none());
        let tool = v.get("tool").and_then(Value::as_str).unwrap();
        assert_eq!(tool.chars().count(), MAX_FIELD_CHARS + "[...]".len());
        assert!(tool.ends_with("[...]"), "a cut is marked");
    }

    #[test]
    fn invisible_and_c1_characters_are_escaped_in_every_text_field() {
        let nasty = "a\u{202e}b\u{200b}c\u{2028}d\u{9b}e\u{85}f\u{feff}g\u{2066}h\u{ad}i\u{2060}j";
        let mut r = record();
        r.token = Some(nasty.into());
        r.peer = Some(nasty.into());
        r.method = nasty.into();
        r.tool = Some(nasty.into());
        r.reason = nasty.into();
        let line = r.to_line();
        for c in [
            '\u{202e}', '\u{200b}', '\u{2028}', '\u{9b}', '\u{85}', '\u{feff}', '\u{2066}',
            '\u{ad}', '\u{2060}',
        ] {
            assert!(!line.contains(c), "{:x} reached the audit line", c as u32);
        }
        assert!(
            line.contains("\\\\u{202e}"),
            "the escape is visible: {line}"
        );
        assert!(parse(&line).is_ok());
    }

    #[test]
    fn outcome_names() {
        assert_eq!(Outcome::Allowed.as_str(), "allowed");
        assert_eq!(Outcome::Denied.as_str(), "denied");
        assert_eq!(Outcome::Error.as_str(), "error");
    }
}
