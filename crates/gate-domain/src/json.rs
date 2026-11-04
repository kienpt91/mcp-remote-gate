//! A strict JSON value, parser and serializer.
//!
//! The gateway re-serializes every message it forwards, so what it inspects is exactly what the
//! other side receives. The parser therefore refuses everything that two parsers could read
//! differently: duplicate object keys, lone surrogates, control characters in strings, leading
//! zeros, trailing data and unbounded nesting. Numbers keep their source text, so integers and
//! floats pass through unchanged.

/// Maximum nesting of arrays and objects.
pub const MAX_DEPTH: usize = 64;
/// Longest accepted number literal.
const MAX_NUMBER_LEN: usize = 100;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// The validated JSON text of the number.
    Number(String),
    String(String),
    Array(Vec<Value>),
    /// Members in source order; keys are unique.
    Object(Vec<(String, Value)>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    UnexpectedEnd,
    UnexpectedByte,
    TrailingData,
    TooDeep,
    DuplicateKey,
    BadEscape,
    BadSurrogate,
    ControlCharacter,
    BadNumber,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError {
    pub offset: usize,
    pub kind: ParseErrorKind,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid JSON at byte {}: {:?}", self.offset, self.kind)
    }
}

impl std::error::Error for ParseError {}

impl Value {
    pub fn str(text: &str) -> Value {
        Value::String(text.to_string())
    }

    pub fn int(n: i64) -> Value {
        Value::Number(n.to_string())
    }

    pub fn uint(n: u64) -> Value {
        Value::Number(n.to_string())
    }

    pub fn object<const N: usize>(members: [(&str, Value); N]) -> Value {
        Value::Object(
            members
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(n) => n.parse().ok(),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Sets a member of an object, replacing an existing one. Does nothing on other values.
    pub fn set(&mut self, key: &str, value: Value) {
        if let Value::Object(members) = self {
            match members.iter_mut().find(|(k, _)| k == key) {
                Some((_, slot)) => *slot = value,
                None => members.push((key.to_string(), value)),
            }
        }
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        match self {
            Value::Object(members) => members.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn remove(&mut self, key: &str) -> Option<Value> {
        match self {
            Value::Object(members) => {
                let at = members.iter().position(|(k, _)| k == key)?;
                Some(members.remove(at).1)
            }
            _ => None,
        }
    }

    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    pub fn write_json(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Number(n) => out.push_str(n),
            Value::String(s) => write_string(s, out),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_json(out);
                }
                out.push(']');
            }
            Value::Object(members) => {
                out.push('{');
                for (i, (k, v)) in members.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(k, out);
                    out.push(':');
                    v.write_json(out);
                }
                out.push('}');
            }
        }
    }
}

/// Appends `s` as a JSON string literal. Control characters and DEL are escaped, everything
/// else is written as is.
pub fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    write_string(s, &mut out);
    out
}

/// Parses one complete JSON document.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    let mut p = Parser {
        text,
        bytes: text.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let value = p.value(0)?;
    p.skip_ws();
    if p.pos < p.bytes.len() {
        return Err(p.err(ParseErrorKind::TrailingData));
    }
    Ok(value)
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn err(&self, kind: ParseErrorKind) -> ParseError {
        ParseError {
            offset: self.pos,
            kind,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), ParseError> {
        match self.peek() {
            Some(b) if b == byte => {
                self.pos += 1;
                Ok(())
            }
            Some(_) => Err(self.err(ParseErrorKind::UnexpectedByte)),
            None => Err(self.err(ParseErrorKind::UnexpectedEnd)),
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, ParseError> {
        let end = self.pos + word.len();
        if self.bytes.get(self.pos..end) == Some(word.as_bytes()) {
            self.pos = end;
            Ok(value)
        } else {
            Err(self.err(ParseErrorKind::UnexpectedByte))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        match self.peek() {
            None => Err(self.err(ParseErrorKind::UnexpectedEnd)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.err(ParseErrorKind::UnexpectedByte)),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth >= MAX_DEPTH {
            return Err(self.err(ParseErrorKind::TooDeep));
        }
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                Some(_) => return Err(self.err(ParseErrorKind::UnexpectedByte)),
                None => return Err(self.err(ParseErrorKind::UnexpectedEnd)),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth >= MAX_DEPTH {
            return Err(self.err(ParseErrorKind::TooDeep));
        }
        self.expect(b'{')?;
        let mut members: Vec<(String, Value)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err(if self.peek().is_none() {
                    ParseErrorKind::UnexpectedEnd
                } else {
                    ParseErrorKind::UnexpectedByte
                }));
            }
            let key_at = self.pos;
            let key = self.string()?;
            if members.iter().any(|(k, _)| *k == key) {
                return Err(ParseError {
                    offset: key_at,
                    kind: ParseErrorKind::DuplicateKey,
                });
            }
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value(depth + 1)?;
            members.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(members));
                }
                Some(_) => return Err(self.err(ParseErrorKind::UnexpectedByte)),
                None => return Err(self.err(ParseErrorKind::UnexpectedEnd)),
            }
        }
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.err(ParseErrorKind::BadNumber)),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err(ParseErrorKind::BadNumber));
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err(ParseErrorKind::BadNumber));
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'0'..=b'9')) {
            // a leading zero followed by more digits, e.g. 01
            return Err(self.err(ParseErrorKind::BadNumber));
        }
        if self.pos - start > MAX_NUMBER_LEN {
            return Err(self.err(ParseErrorKind::BadNumber));
        }
        let literal = self.text.get(start..self.pos).unwrap_or_default();
        Ok(Value::Number(literal.to_string()))
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let mut n = 0u32;
        for _ in 0..4 {
            let digit = match self.peek() {
                Some(c @ b'0'..=b'9') => c - b'0',
                Some(c @ b'a'..=b'f') => c - b'a' + 10,
                Some(c @ b'A'..=b'F') => c - b'A' + 10,
                _ => return Err(self.err(ParseErrorKind::BadEscape)),
            };
            n = n << 4 | u32::from(digit);
            self.pos += 1;
        }
        Ok(n)
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let run_start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            // the run stops at ASCII bytes only, so both ends are character boundaries
            out.push_str(self.text.get(run_start..self.pos).unwrap_or_default());
            match self.peek() {
                None => return Err(self.err(ParseErrorKind::UnexpectedEnd)),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let escape = self
                        .peek()
                        .ok_or_else(|| self.err(ParseErrorKind::UnexpectedEnd))?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => {
                            self.pos -= 1;
                            return Err(self.err(ParseErrorKind::BadEscape));
                        }
                    }
                }
                Some(_) => return Err(self.err(ParseErrorKind::ControlCharacter)),
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, ParseError> {
        let first = self.hex4()?;
        let code = match first {
            0xd800..=0xdbff => {
                if self.bytes.get(self.pos..self.pos + 2) != Some(b"\\u") {
                    return Err(self.err(ParseErrorKind::BadSurrogate));
                }
                self.pos += 2;
                let second = self.hex4()?;
                if !(0xdc00..=0xdfff).contains(&second) {
                    return Err(self.err(ParseErrorKind::BadSurrogate));
                }
                0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
            }
            0xdc00..=0xdfff => return Err(self.err(ParseErrorKind::BadSurrogate)),
            other => other,
        };
        char::from_u32(code).ok_or_else(|| self.err(ParseErrorKind::BadSurrogate))
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

    fn kind(text: &str) -> ParseErrorKind {
        parse(text).unwrap_err().kind
    }

    #[test]
    fn parses_scalars_and_containers() {
        assert_eq!(parse(" null ").unwrap(), Value::Null);
        assert_eq!(parse("true").unwrap(), Value::Bool(true));
        assert_eq!(
            parse("[1, -2.5e3, \"x\"]").unwrap().to_json(),
            "[1,-2.5e3,\"x\"]"
        );
        let v = parse("{\"a\":{\"b\":[]},\"c\":false}").unwrap();
        assert_eq!(
            v.get("a").and_then(|a| a.get("b")),
            Some(&Value::Array(vec![]))
        );
        assert_eq!(v.get("c").and_then(Value::as_bool), Some(false));
        assert_eq!(v.get("missing"), None);
    }

    #[test]
    fn numbers_keep_their_text() {
        let big = "123456789012345678901234567890.000100e-5";
        assert_eq!(parse(big).unwrap(), Value::Number(big.to_string()));
        assert_eq!(
            parse("18446744073709551615").unwrap().as_u64(),
            Some(u64::MAX)
        );
        assert_eq!(parse("-1").unwrap().as_u64(), None);
        assert_eq!(parse("1.5").unwrap().as_u64(), None);
    }

    #[test]
    fn rejects_bad_numbers() {
        for bad in [
            "01", "-", "1.", ".5", "1e", "1e+", "+1", "0x10", "--1", "1.2.3", "NaN", "Infinity",
            "-01",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert_eq!(
            kind(&format!("1{}", "0".repeat(120))),
            ParseErrorKind::BadNumber
        );
    }

    #[test]
    fn string_escapes() {
        assert_eq!(
            parse(r#""a\"b\\c\/d\n\t\u00e9\ud83d\ude00""#).unwrap(),
            Value::str("a\"b\\c/d\n\té😀")
        );
        assert_eq!(
            parse("\"héllo wörld ✓\"").unwrap(),
            Value::str("héllo wörld ✓")
        );
    }

    #[test]
    fn rejects_bad_strings() {
        assert_eq!(kind(r#""\ud800""#), ParseErrorKind::BadSurrogate);
        assert_eq!(kind(r#""\udc00""#), ParseErrorKind::BadSurrogate);
        assert_eq!(kind(r#""\ud800\u0041""#), ParseErrorKind::BadSurrogate);
        assert_eq!(kind(r#""\x41""#), ParseErrorKind::BadEscape);
        assert_eq!(kind(r#""\u12G4""#), ParseErrorKind::BadEscape);
        assert_eq!(kind("\"a\u{1}b\""), ParseErrorKind::ControlCharacter);
        assert_eq!(kind("\"a\nb\""), ParseErrorKind::ControlCharacter);
        assert_eq!(kind("\"abc"), ParseErrorKind::UnexpectedEnd);
        assert_eq!(kind("\"abc\\"), ParseErrorKind::UnexpectedEnd);
    }

    #[test]
    fn rejects_structural_errors() {
        for bad in [
            "",
            " ",
            "[",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "{\"a\"}",
            "{a:1}",
            "[1 2]",
            "nul",
            "truee",
            "'a'",
            "{\"a\":1}}",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(kind("1 2"), ParseErrorKind::TrailingData);
    }

    #[test]
    fn duplicate_keys_are_refused() {
        assert_eq!(kind(r#"{"a":1,"a":2}"#), ParseErrorKind::DuplicateKey);
        assert_eq!(
            kind(r#"{"a":1,"b":{"c":1,"c":1}}"#),
            ParseErrorKind::DuplicateKey
        );
        // keys that only look alike after decoding collide as well
        assert_eq!(kind(r#"{"a":1,"\u0061":2}"#), ParseErrorKind::DuplicateKey);
    }

    #[test]
    fn nesting_is_bounded_without_overflowing_the_stack() {
        let ok = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse(&ok).is_ok());
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert_eq!(kind(&deep), ParseErrorKind::TooDeep);
        assert_eq!(kind(&"[".repeat(1_000_000)), ParseErrorKind::TooDeep);
        assert_eq!(kind(&"{\"a\":".repeat(100_000)), ParseErrorKind::TooDeep);
    }

    #[test]
    fn serializer_escapes_controls() {
        assert_eq!(
            quote("a\"\\\n\r\t\u{1}\u{7f}é"),
            "\"a\\\"\\\\\\n\\r\\t\\u0001\\u007fé\""
        );
        // the output of the serializer never contains a raw control character
        let v = Value::str("\u{0}\u{1b}[31mred\u{1b}[0m\u{8}\u{c}");
        assert!(v
            .to_json()
            .chars()
            .all(|c| (c as u32) >= 0x20 && c != '\u{7f}'));
        assert_eq!(parse(&v.to_json()).unwrap(), v);
    }

    #[test]
    fn roundtrip_property_over_generated_values() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        fn gen(next: &mut dyn FnMut() -> u64, depth: usize) -> Value {
            let pick = next() % if depth >= 4 { 5 } else { 7 };
            match pick {
                0 => Value::Null,
                1 => Value::Bool(next().is_multiple_of(2)),
                2 => Value::int((next() as i64) >> (next() % 60)),
                3 => Value::Number(format!(
                    "{}.{}e{}",
                    next() % 1000,
                    next() % 1000,
                    (next() % 20) as i64 - 10
                )),
                4 => {
                    let alphabet = [
                        'a', 'Z', '0', ' ', '"', '\\', '\n', '\u{1}', 'é', '✓', '😀', '/',
                    ];
                    let len = next() % 12;
                    Value::String(
                        (0..len)
                            .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                            .collect(),
                    )
                }
                5 => Value::Array((0..next() % 4).map(|_| gen(next, depth + 1)).collect()),
                _ => {
                    let mut members: Vec<(String, Value)> = Vec::new();
                    for i in 0..next() % 4 {
                        members.push((format!("k{i}\u{e9}\n"), gen(next, depth + 1)));
                    }
                    Value::Object(members)
                }
            }
        }
        for _ in 0..500 {
            let v = gen(&mut next, 0);
            let text = v.to_json();
            assert_eq!(parse(&text).unwrap(), v, "{text}");
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut seed = 0x1234_5678_9abc_def1u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let pieces = [
            "{", "}", "[", "]", "\"", "\\", ",", ":", "1", "-", "e", "tru", "null", "\\u", "d800",
            " ", "é", "\u{0}",
        ];
        for _ in 0..3000 {
            let text: String = (0..next() % 30)
                .map(|_| pieces[(next() % pieces.len() as u64) as usize])
                .collect();
            let _ = parse(&text);
        }
    }

    #[test]
    fn object_helpers() {
        let mut v = Value::object([("a", Value::int(1))]);
        v.set("b", Value::Bool(true));
        v.set("a", Value::int(2));
        assert_eq!(v.to_json(), "{\"a\":2,\"b\":true}");
        assert_eq!(v.remove("a"), Some(Value::int(2)));
        assert_eq!(v.remove("a"), None);
        assert!(v.get_mut("b").is_some());
        let mut not_object = Value::Null;
        not_object.set("x", Value::Null);
        assert!(not_object.is_null());
        assert_eq!(Value::uint(7).as_u64(), Some(7));
    }
}
