//! A parser for the subset of TOML that the configuration uses.
//!
//! Supported: comments, `[table]` and `[[array of tables]]` headers with dotted paths, `key =
//! value` with bare or quoted keys, basic and literal strings (single line), integers, booleans,
//! arrays of scalars (also over several lines, with a trailing comma) and single-line inline
//! tables of scalars. Everything else (floats, dates, multi-line strings, dotted keys) is
//! rejected with a message and a line number rather than guessed at. Duplicate keys and tables
//! that are defined twice are errors, so a configuration cannot say two things at once.

/// Largest file the parser accepts.
pub const MAX_BYTES: usize = 256 * 1024;
const MAX_DEPTH: usize = 8;
const MAX_ITEMS: usize = 4096;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    Array(Vec<Value>),
    Table(Table),
    /// Written with `[[name]]` headers.
    Tables(Vec<Table>),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Table {
    pub entries: Vec<(String, Value)>,
    /// Set when the table was named by a header or an inline table, not only created on the way
    /// to a deeper one.
    defined: bool,
}

impl Table {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.entries
            .iter_mut()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TomlError {
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for TomlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for TomlError {}

struct Cursor<'a> {
    /// The unparsed rest of the document.
    rest: &'a str,
    line: usize,
}

fn err<T>(line: usize, message: &str) -> Result<T, TomlError> {
    Err(TomlError {
        line,
        message: message.to_string(),
    })
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<char> {
        self.rest.chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.rest.chars().next()?;
        self.rest = self.rest.get(c.len_utf8()..).unwrap_or_default();
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }

    fn skip_spaces(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.bump();
        }
    }

    /// Skips spaces, newlines and comments (inside arrays).
    fn skip_blank(&mut self) {
        loop {
            match self.peek() {
                Some(' ' | '\t' | '\r' | '\n') => {
                    self.bump();
                }
                Some('#') => self.skip_comment(),
                _ => return,
            }
        }
    }

    fn skip_comment(&mut self) {
        while let Some(c) = self.peek() {
            if c == '\n' {
                return;
            }
            self.bump();
        }
    }

    /// The end of a statement: spaces, an optional comment, then a newline or the end.
    fn end_of_line(&mut self) -> Result<(), TomlError> {
        self.skip_spaces();
        if self.peek() == Some('#') {
            self.skip_comment();
        }
        match self.peek() {
            None => Ok(()),
            Some('\n') => {
                self.bump();
                Ok(())
            }
            Some('\r') => {
                self.bump();
                if self.peek() == Some('\n') {
                    self.bump();
                    Ok(())
                } else {
                    err(self.line, "a carriage return must be followed by a newline")
                }
            }
            Some(_) => err(self.line, "unexpected text after the value"),
        }
    }

    fn bare_key(&mut self) -> String {
        let mut key = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                key.push(c);
                self.bump();
            } else {
                break;
            }
        }
        key
    }

    fn key(&mut self) -> Result<String, TomlError> {
        match self.peek() {
            Some('"') => self.basic_string(),
            Some('\'') => self.literal_string(),
            _ => {
                let key = self.bare_key();
                if key.is_empty() {
                    return err(self.line, "expected a key");
                }
                Ok(key)
            }
        }
    }

    fn basic_string(&mut self) -> Result<String, TomlError> {
        let line = self.line;
        self.bump();
        if self.rest.starts_with("\"\"") {
            return err(line, "multi-line strings are not supported");
        }
        let mut out = String::new();
        loop {
            match self.bump() {
                None | Some('\n') => return err(line, "unterminated string"),
                Some('"') => return Ok(out),
                Some('\\') => match self.bump() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('r') => out.push('\r'),
                    Some('b') => out.push('\u{8}'),
                    Some('f') => out.push('\u{c}'),
                    Some('u') => out.push(self.unicode(4, line)?),
                    Some('U') => out.push(self.unicode(8, line)?),
                    _ => return err(line, "unknown escape in string"),
                },
                Some(c) if c.is_control() && c != '\t' => {
                    return err(line, "control character in string")
                }
                Some(c) => out.push(c),
            }
        }
    }

    fn unicode(&mut self, digits: usize, line: usize) -> Result<char, TomlError> {
        let mut n = 0u32;
        for _ in 0..digits {
            let d = self.bump().and_then(|c| c.to_digit(16));
            match d {
                Some(d) => {
                    n = n
                        .checked_mul(16)
                        .and_then(|n| n.checked_add(d))
                        .unwrap_or(u32::MAX)
                }
                None => return err(line, "bad unicode escape"),
            }
        }
        char::from_u32(n).map_or_else(|| err(line, "bad unicode escape"), Ok)
    }

    fn literal_string(&mut self) -> Result<String, TomlError> {
        let line = self.line;
        self.bump();
        if self.rest.starts_with("''") {
            return err(line, "multi-line strings are not supported");
        }
        let mut out = String::new();
        loop {
            match self.bump() {
                None | Some('\n') => return err(line, "unterminated string"),
                Some('\'') => return Ok(out),
                Some(c) if c.is_control() && c != '\t' => {
                    return err(line, "control character in string")
                }
                Some(c) => out.push(c),
            }
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, TomlError> {
        if depth > MAX_DEPTH {
            return err(self.line, "values are nested too deeply");
        }
        match self.peek() {
            Some('"') => Ok(Value::Str(self.basic_string()?)),
            Some('\'') => Ok(Value::Str(self.literal_string()?)),
            Some('[') => self.array(depth),
            Some('{') => self.inline_table(depth),
            Some(c) if c.is_ascii_digit() || c == '-' || c == '+' => self.integer(),
            Some(c) if c.is_ascii_alphabetic() => {
                let word = self.bare_key();
                match word.as_str() {
                    "true" => Ok(Value::Bool(true)),
                    "false" => Ok(Value::Bool(false)),
                    _ => err(self.line, "unsupported value (strings need quotes)"),
                }
            }
            _ => err(self.line, "expected a value"),
        }
    }

    fn integer(&mut self) -> Result<Value, TomlError> {
        let line = self.line;
        let mut text = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '-' | '.' | ':') {
                text.push(c);
                self.bump();
            } else {
                break;
            }
        }
        let clean = text.replace('_', "");
        if text.starts_with('_') || text.ends_with('_') || text.contains("__") {
            return err(line, "bad number");
        }
        match clean.parse::<i64>() {
            Ok(n) if !(clean.len() > 1 && (clean.starts_with("0") || clean.starts_with("+0") || clean.starts_with("-0"))) => Ok(Value::Int(n)),
            _ if clean == "0" || clean == "+0" || clean == "-0" => Ok(Value::Int(0)),
            _ => err(line, "only plain decimal integers are supported (no floats, dates, hex or leading zeros)"),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, TomlError> {
        self.bump();
        let mut items = Vec::new();
        loop {
            self.skip_blank();
            match self.peek() {
                None => return err(self.line, "unterminated array"),
                Some(']') => {
                    self.bump();
                    return Ok(Value::Array(items));
                }
                _ => {}
            }
            if items.len() >= MAX_ITEMS {
                return err(self.line, "too many array items");
            }
            let item = self.value(depth + 1)?;
            if matches!(item, Value::Table(_)) {
                return err(self.line, "tables inside arrays are not supported");
            }
            items.push(item);
            self.skip_blank();
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some(']') => {}
                _ => return err(self.line, "expected , or ] in the array"),
            }
        }
    }

    fn inline_table(&mut self, depth: usize) -> Result<Value, TomlError> {
        self.bump();
        let mut table = Table {
            defined: true,
            ..Table::default()
        };
        self.skip_spaces();
        if self.peek() == Some('}') {
            self.bump();
            return Ok(Value::Table(table));
        }
        loop {
            self.skip_spaces();
            let key = self.key()?;
            self.skip_spaces();
            if self.peek() != Some('=') {
                return err(self.line, "expected = after the key");
            }
            self.bump();
            self.skip_spaces();
            let value = self.value(depth + 1)?;
            if table.get(&key).is_some() {
                return err(self.line, &format!("duplicate key `{key}`"));
            }
            table.entries.push((key, value));
            self.skip_spaces();
            match self.bump() {
                Some(',') => {}
                Some('}') => return Ok(Value::Table(table)),
                _ => return err(self.line, "expected , or } in the inline table"),
            }
        }
    }

    fn header_path(&mut self, closing: &str) -> Result<Vec<String>, TomlError> {
        let mut path = Vec::new();
        loop {
            self.skip_spaces();
            path.push(self.key()?);
            self.skip_spaces();
            if self.rest.starts_with(closing) {
                for _ in closing.chars() {
                    self.bump();
                }
                return Ok(path);
            }
            if self.peek() != Some('.') {
                return err(self.line, "expected . or the end of the table header");
            }
            self.bump();
        }
    }
}

/// Parses `text` into the root table.
pub fn parse(text: &str) -> Result<Table, TomlError> {
    if text.len() > MAX_BYTES {
        return err(1, "the file is too large");
    }
    let mut cur = Cursor {
        rest: text.strip_prefix('\u{feff}').unwrap_or(text),
        line: 1,
    };
    let mut root = Table {
        defined: true,
        ..Table::default()
    };
    let mut current: Vec<String> = Vec::new();
    loop {
        cur.skip_blank();
        let line = cur.line;
        match cur.peek() {
            None => return Ok(root),
            Some('[') => {
                cur.bump();
                let is_array = cur.peek() == Some('[');
                if is_array {
                    cur.bump();
                }
                let path = cur.header_path(if is_array { "]]" } else { "]" })?;
                cur.end_of_line()?;
                open_table(&mut root, &path, is_array, line)?;
                current = path;
            }
            Some(_) => {
                let key = cur.key()?;
                cur.skip_spaces();
                match cur.peek() {
                    Some('=') => {
                        cur.bump();
                    }
                    Some('.') => {
                        return err(line, "dotted keys are not supported: use a [table] header")
                    }
                    _ => return err(line, "expected = after the key"),
                }
                cur.skip_spaces();
                let value = cur.value(0)?;
                cur.end_of_line()?;
                let table = navigate(&mut root, &current, line)?;
                if table.get(&key).is_some() {
                    return err(line, &format!("duplicate key `{key}`"));
                }
                if table.entries.len() >= MAX_ITEMS {
                    return err(line, "too many keys in one table");
                }
                table.entries.push((key, value));
            }
        }
    }
}

/// The table at `path`, following the last element of arrays of tables.
fn navigate<'t>(
    root: &'t mut Table,
    path: &[String],
    line: usize,
) -> Result<&'t mut Table, TomlError> {
    let mut table = root;
    for segment in path {
        let next = table.get_mut(segment);
        table = match next {
            Some(Value::Table(t)) => t,
            Some(Value::Tables(list)) => match list.last_mut() {
                Some(t) => t,
                None => return err(line, "empty array of tables"),
            },
            _ => return err(line, &format!("`{segment}` is not a table")),
        };
    }
    Ok(table)
}

fn open_table(
    root: &mut Table,
    path: &[String],
    is_array: bool,
    line: usize,
) -> Result<(), TomlError> {
    let Some((last, parents)) = path.split_last() else {
        return err(line, "empty table header");
    };
    // intermediate tables are created on demand
    let mut table = root;
    for segment in parents {
        if table.get(segment).is_none() {
            table
                .entries
                .push((segment.clone(), Value::Table(Table::default())));
        }
        table = match table.get_mut(segment) {
            Some(Value::Table(t)) => t,
            Some(Value::Tables(list)) => match list.last_mut() {
                Some(t) => t,
                None => return err(line, "empty array of tables"),
            },
            _ => return err(line, &format!("`{segment}` is not a table")),
        };
    }
    match (table.get_mut(last), is_array) {
        (None, false) => table.entries.push((
            last.clone(),
            Value::Table(Table {
                defined: true,
                ..Table::default()
            }),
        )),
        (None, true) => table.entries.push((
            last.clone(),
            Value::Tables(vec![Table {
                defined: true,
                ..Table::default()
            }]),
        )),
        (Some(Value::Table(t)), false) if !t.defined => t.defined = true,
        (Some(Value::Table(_)), false) => {
            return err(line, &format!("the table `{last}` is defined twice"))
        }
        (Some(Value::Tables(list)), true) => list.push(Table {
            defined: true,
            ..Table::default()
        }),
        _ => {
            return err(
                line,
                &format!("`{last}` is already defined as something else"),
            )
        }
    }
    Ok(())
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

    fn ok(text: &str) -> Table {
        parse(text).unwrap_or_else(|e| panic!("{e} in {text:?}"))
    }

    fn bad(text: &str) -> TomlError {
        parse(text).unwrap_err()
    }

    fn get<'a>(t: &'a Table, path: &str) -> &'a Value {
        let mut value: Option<&Value> = None;
        let mut table = t;
        for part in path.split('.') {
            let v = table
                .get(part)
                .unwrap_or_else(|| panic!("no {part} in {path}"));
            if let Value::Table(inner) = v {
                table = inner;
            }
            value = Some(v);
        }
        value.unwrap()
    }

    #[test]
    fn scalars() {
        let t = ok("a = \"x\\ty\\u00e9\\\"\"\nb = 'lit\\eral'\nc = 42\nd = -7\ne = true\nf = false\ng = 1_000\nh = +5\ni = 0\n");
        assert_eq!(get(&t, "a"), &Value::Str("x\ty\u{e9}\"".into()));
        assert_eq!(get(&t, "b"), &Value::Str("lit\\eral".into()));
        assert_eq!(get(&t, "c"), &Value::Int(42));
        assert_eq!(get(&t, "d"), &Value::Int(-7));
        assert_eq!(get(&t, "e"), &Value::Bool(true));
        assert_eq!(get(&t, "f"), &Value::Bool(false));
        assert_eq!(get(&t, "g"), &Value::Int(1000));
        assert_eq!(get(&t, "h"), &Value::Int(5));
        assert_eq!(get(&t, "i"), &Value::Int(0));
    }

    #[test]
    fn comments_blank_lines_and_crlf() {
        let t =
            ok("# top\r\n\r\na = 1 # trailing\r\n\r\n  # indented\r\nb = \"# not a comment\"\r\n");
        assert_eq!(get(&t, "a"), &Value::Int(1));
        assert_eq!(get(&t, "b"), &Value::Str("# not a comment".into()));
        assert_eq!(ok("\u{feff}a = 1").entries.len(), 1);
        assert!(ok("").entries.is_empty());
        assert!(ok("a = 1").get("a").is_some());
    }

    #[test]
    fn arrays_over_several_lines() {
        let t =
            ok("a = [\n  \"x\", # first\n  \"y\",\n]\nb = []\nc = [1, 2]\nd = [[1], [\"a\"]]\n");
        assert_eq!(
            get(&t, "a"),
            &Value::Array(vec![Value::Str("x".into()), Value::Str("y".into())])
        );
        assert_eq!(get(&t, "b"), &Value::Array(vec![]));
        assert_eq!(
            get(&t, "c"),
            &Value::Array(vec![Value::Int(1), Value::Int(2)])
        );
        assert!(matches!(get(&t, "d"), Value::Array(v) if v.len() == 2));
    }

    #[test]
    fn tables_and_nesting() {
        let t = ok("[server]\nlisten = \"x\"\n[child]\ncommand = [\"a\"]\n[child.env]\nK = \"v\"\n[a.b.c]\nd = 1\n");
        assert_eq!(get(&t, "server.listen"), &Value::Str("x".into()));
        assert_eq!(get(&t, "child.env.K"), &Value::Str("v".into()));
        assert_eq!(get(&t, "a.b.c.d"), &Value::Int(1));
    }

    #[test]
    fn a_parent_header_may_follow_its_child() {
        let t = ok("[a.b]\nx = 1\n[a]\ny = 2\n");
        assert_eq!(get(&t, "a.y"), &Value::Int(2));
        assert_eq!(get(&t, "a.b.x"), &Value::Int(1));
    }

    #[test]
    fn arrays_of_tables() {
        let t = ok("[[token]]\nid = \"a\"\n[[token]]\nid = \"b\"\n[token.extra]\nx = 1\n");
        let Value::Tables(list) = t.get("token").unwrap() else {
            panic!()
        };
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].get("id"), Some(&Value::Str("a".into())));
        assert!(matches!(list[1].get("extra"), Some(Value::Table(_))));
        assert!(list[0].get("extra").is_none());
    }

    #[test]
    fn inline_tables() {
        let t = ok("env = { A = \"1\", \"B-C\" = 'x', n = 2 }\ne = {}\n");
        let Value::Table(env) = t.get("env").unwrap() else {
            panic!()
        };
        assert_eq!(env.get("A"), Some(&Value::Str("1".into())));
        assert_eq!(env.get("B-C"), Some(&Value::Str("x".into())));
        assert_eq!(env.get("n"), Some(&Value::Int(2)));
        assert!(matches!(t.get("e"), Some(Value::Table(e)) if e.entries.is_empty()));
    }

    #[test]
    fn quoted_keys() {
        let t = ok("\"a b\" = 1\n'c' = 2\n[\"x y\"]\nk = 3\n");
        assert_eq!(t.get("a b"), Some(&Value::Int(1)));
        assert_eq!(t.get("c"), Some(&Value::Int(2)));
        assert!(t.get("x y").is_some());
    }

    #[test]
    fn duplicates_are_errors() {
        assert!(bad("a = 1\na = 2").message.contains("duplicate"));
        assert!(bad("[a]\nx = 1\n[a]\ny = 2").message.contains("twice"));
        assert!(bad("[a]\nx = 1\n[a.x]\n")
            .message
            .contains("something else"));
        assert!(bad("a = 1\n[a]\n").message.contains("something else"));
        assert!(bad("[[a]]\n[a]\n").message.contains("something else"));
        assert!(bad("e = { a = 1, a = 2 }").message.contains("duplicate"));
        assert!(bad("[a]\n[a]").line == 2);
    }

    #[test]
    fn unsupported_features_are_named() {
        assert!(bad("a = 1.5").message.contains("only plain decimal"));
        assert!(bad("a = 1979-05-27").message.contains("only plain decimal"));
        assert!(bad("a = 0x10").message.contains("only plain decimal"));
        assert!(bad("a = 007").message.contains("only plain decimal"));
        assert!(bad("a = \"\"\"x\"\"\"").message.contains("multi-line"));
        assert!(bad("a = '''x'''").message.contains("multi-line"));
        assert!(bad("a.b = 1").message.contains("dotted keys"));
        assert!(bad("a = bare").message.contains("quotes"));
        assert!(bad("a = [{ x = 1 }]").message.contains("not supported"));
        assert!(bad("a = 1_").message.contains("bad number"));
    }

    #[test]
    fn syntax_errors_carry_line_numbers() {
        assert_eq!(bad("a = 1\nb = \n").line, 2);
        assert_eq!(bad("\n\n[a\n").line, 3);
        assert_eq!(bad("a = \"x\nb = 1").line, 1);
        assert_eq!(bad("a = [\n1,\n2\n").line, 4);
        for text in [
            "a",
            "= 1",
            "a = ",
            "[]",
            "[a] x",
            "a = 1 b = 2",
            "a = \"\\q\"",
            "a = \"\\u12\"",
            "a = \"\\ud800\"",
            "a = \"x\u{1}\"",
            "a = 'x\u{1}'",
            "[[a]",
            "a = {",
            "a = { b }",
            "a = [1 2]",
            "a = 1\r b = 2",
            "[a.]",
            "[.a]",
            "[a..b]",
        ] {
            assert!(parse(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn hostile_input_terminates() {
        assert!(parse(&"[".repeat(100_000)).is_err());
        assert!(parse(&format!("a = {}", "[".repeat(100_000))).is_err());
        assert!(parse(&format!("a = {}", "{ a = ".repeat(1000))).is_err());
        assert!(parse(&"a".repeat(MAX_BYTES + 1)).is_err());
        let many = (0..5000)
            .map(|i| format!("k{i} = {i}\n"))
            .collect::<String>();
        assert!(parse(&many).is_err(), "too many keys");
        let long_array = format!("a = [{}]", "1,".repeat(5000));
        assert!(parse(&long_array).is_err());
    }
}
