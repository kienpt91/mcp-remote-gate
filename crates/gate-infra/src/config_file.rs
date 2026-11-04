//! Reading `gate.toml`: the file checks, the mapping of the TOML tables onto the raw
//! configuration (unknown keys and wrong types are errors, never ignored) and the resolution of
//! relative paths against the directory of the file.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use gate_domain::config::{
    Config, RawAudit, RawChild, RawConfig, RawLimits, RawRule, RawServer, RawToken, RawTools,
};

use crate::toml::{self, Table, Value};

struct Section {
    path: String,
    entries: Vec<(String, Value)>,
}

impl Section {
    fn new(path: &str, table: &Table) -> Section {
        Section {
            path: path.to_string(),
            entries: table.entries.clone(),
        }
    }

    fn take(&mut self, key: &str) -> Option<Value> {
        let at = self.entries.iter().position(|(k, _)| k == key)?;
        Some(self.entries.remove(at).1)
    }

    fn at(&self, key: &str) -> String {
        if self.path.is_empty() {
            key.to_string()
        } else {
            format!("{}.{key}", self.path)
        }
    }

    fn str(&mut self, key: &str, p: &mut Vec<String>) -> Option<String> {
        match self.take(key)? {
            Value::Str(s) => Some(s),
            _ => {
                p.push(format!("{}: expected a string", self.at(key)));
                None
            }
        }
    }

    fn int(&mut self, key: &str, p: &mut Vec<String>) -> Option<i64> {
        match self.take(key)? {
            Value::Int(n) => Some(n),
            _ => {
                p.push(format!("{}: expected an integer", self.at(key)));
                None
            }
        }
    }

    fn bool(&mut self, key: &str, p: &mut Vec<String>) -> Option<bool> {
        match self.take(key)? {
            Value::Bool(b) => Some(b),
            _ => {
                p.push(format!("{}: expected true or false", self.at(key)));
                None
            }
        }
    }

    fn str_list(&mut self, key: &str, p: &mut Vec<String>) -> Option<Vec<String>> {
        match self.take(key)? {
            Value::Array(items) => {
                let mut out = Vec::new();
                for item in items {
                    match item {
                        Value::Str(s) => out.push(s),
                        _ => {
                            p.push(format!("{}: every item must be a string", self.at(key)));
                            return None;
                        }
                    }
                }
                Some(out)
            }
            _ => {
                p.push(format!("{}: expected a list of strings", self.at(key)));
                None
            }
        }
    }

    fn table(&mut self, key: &str, p: &mut Vec<String>) -> Option<Section> {
        match self.take(key)? {
            Value::Table(t) => Some(Section::new(&self.at(key), &t)),
            _ => {
                p.push(format!("{}: expected a table", self.at(key)));
                None
            }
        }
    }

    fn tables(&mut self, key: &str, p: &mut Vec<String>) -> Vec<Section> {
        match self.take(key) {
            None => Vec::new(),
            Some(Value::Tables(list)) => list
                .iter()
                .enumerate()
                .map(|(i, t)| Section::new(&format!("{}[{i}]", self.at(key)), t))
                .collect(),
            Some(_) => {
                p.push(format!("{}: expected [[{key}]] tables", self.at(key)));
                Vec::new()
            }
        }
    }

    /// Reports every key that was not taken.
    fn finish(self, p: &mut Vec<String>) {
        for (key, _) in &self.entries {
            p.push(format!("{}: unknown key", self.at(key)));
        }
    }
}

/// Maps a parsed document to the raw configuration; every problem is collected.
pub fn raw_config(root: &Table) -> Result<RawConfig, Vec<String>> {
    let mut p = Vec::new();
    let mut top = Section::new("", root);
    let mut raw = RawConfig::default();

    if let Some(mut s) = top.table("server", &mut p) {
        raw.server = RawServer {
            listen: s.str("listen", &mut p),
            endpoint: s.str("endpoint", &mut p),
            allowed_hosts: s.str_list("allowed_hosts", &mut p),
            allowed_origins: s.str_list("allowed_origins", &mut p),
            max_request_bytes: s.int("max_request_bytes", &mut p),
            request_timeout_ms: s.int("request_timeout_ms", &mut p),
            header_timeout_ms: s.int("header_timeout_ms", &mut p),
            idle_timeout_ms: s.int("idle_timeout_ms", &mut p),
            max_connections: s.int("max_connections", &mut p),
            kill_switch_file: s.str("kill_switch_file", &mut p),
        };
        s.finish(&mut p);
    }
    if let Some(mut s) = top.table("child", &mut p) {
        let mut env = Vec::new();
        if let Some(mut e) = s.table("env", &mut p) {
            let keys: Vec<String> = e.entries.iter().map(|(k, _)| k.clone()).collect();
            for key in keys {
                if let Some(value) = e.str(&key, &mut p) {
                    env.push((key, value));
                }
            }
            e.finish(&mut p);
        }
        raw.child = RawChild {
            command: s.str_list("command", &mut p),
            cwd: s.str("cwd", &mut p),
            env,
            inherit_env: s.str_list("inherit_env", &mut p),
            restart: s.str("restart", &mut p),
            max_restarts: s.int("max_restarts", &mut p),
            restart_backoff_ms: s.int("restart_backoff_ms", &mut p),
            max_line_bytes: s.int("max_line_bytes", &mut p),
            startup_timeout_ms: s.int("startup_timeout_ms", &mut p),
            shutdown_grace_ms: s.int("shutdown_grace_ms", &mut p),
            memory_mb: s.int("memory_mb", &mut p),
            cpu_seconds: s.int("cpu_seconds", &mut p),
            max_open_files: s.int("max_open_files", &mut p),
            max_file_mb: s.int("max_file_mb", &mut p),
        };
        s.finish(&mut p);
    }
    if let Some(mut s) = top.table("tools", &mut p) {
        let mut rules = Vec::new();
        for mut r in s.tables("rule", &mut p) {
            rules.push(RawRule {
                tool: r.str("tool", &mut p),
                max_arg_bytes: r.int("max_arg_bytes", &mut p),
                max_string_len: r.int("max_string_len", &mut p),
                forbid_values: r.str_list("forbid_values", &mut p),
            });
            r.finish(&mut p);
        }
        raw.tools = RawTools {
            allow: s.str_list("allow", &mut p),
            deny: s.str_list("deny", &mut p),
            read_only: s.bool("read_only", &mut p),
            read_patterns: s.str_list("read_patterns", &mut p),
            rules,
        };
        s.finish(&mut p);
    }
    if let Some(mut s) = top.table("limits", &mut p) {
        raw.limits = RawLimits {
            requests_per_minute: s.int("requests_per_minute", &mut p),
            burst: s.int("burst", &mut p),
            result_max_bytes: s.int("result_max_bytes", &mut p),
            tool_result_prefix: s.str("tool_result_prefix", &mut p),
            max_inflight: s.int("max_inflight", &mut p),
            failed_auth_per_minute: s.int("failed_auth_per_minute", &mut p),
        };
        s.finish(&mut p);
    }
    if let Some(mut s) = top.table("audit", &mut p) {
        raw.audit = RawAudit {
            path: s.str("path", &mut p),
            log_arguments: s.bool("log_arguments", &mut p),
            arguments_max_chars: s.int("arguments_max_chars", &mut p),
        };
        s.finish(&mut p);
    }
    for mut t in top.tables("token", &mut p) {
        raw.tokens.push(RawToken {
            id: t.str("id", &mut p),
            hash: t.str("hash", &mut p),
            scopes: t.str_list("scopes", &mut p),
            tools: t.str_list("tools", &mut p),
        });
        t.finish(&mut p);
    }
    top.finish(&mut p);
    if p.is_empty() {
        Ok(raw)
    } else {
        Err(p)
    }
}

/// Parses and validates the text of a configuration file. Relative paths are left as written.
pub fn parse_config(text: &str) -> Result<Config, Vec<String>> {
    let table = toml::parse(text).map_err(|e| vec![e.to_string()])?;
    Config::build(raw_config(&table)?)
}

fn resolve(base: &Path, path: &str) -> String {
    let p = Path::new(path);
    if p.is_absolute() {
        path.to_string()
    } else {
        base.join(p).to_string_lossy().into_owned()
    }
}

/// Reads, checks and validates the configuration file at `path`. Relative paths of the audit
/// log, the kill switch file, the working directory and a relative program (`./server`) are
/// taken relative to the directory of the file.
pub fn load(path: &Path) -> Result<Config, Vec<String>> {
    let meta = std::fs::metadata(path)
        .map_err(|e| vec![format!("cannot read {}: {e}", path.display())])?;
    if !meta.is_file() {
        return Err(vec![format!("{} is not a file", path.display())]);
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(vec![format!(
            "{} can be written by other users: anyone who can edit it can widen the tool policy; run chmod go-w on it",
            path.display()
        )]);
    }
    if meta.len() > toml::MAX_BYTES as u64 {
        return Err(vec![format!(
            "{} is larger than {} bytes",
            path.display(),
            toml::MAX_BYTES
        )]);
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| vec![format!("cannot read {}: {e}", path.display())])?;
    let mut config = parse_config(&text)?;
    let base = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    config.audit.path = resolve(base, &config.audit.path);
    if let Some(f) = &config.server.kill_switch_file {
        config.server.kill_switch_file = Some(resolve(base, f));
    }
    if let Some(c) = &config.child.cwd {
        config.child.cwd = Some(resolve(base, c));
    }
    if let Some(program) = config.child.command.first_mut() {
        if program.starts_with("./") || program.starts_with("../") {
            *program = resolve(base, program);
        }
    }
    Ok(config)
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
    use crate::testutil::TempDir;
    use gate_domain::auth::{token_from_entropy, TokenHash};

    fn token_block() -> String {
        format!(
            "[[token]]\nid = \"desktop\"\nhash = \"{}\"\n",
            TokenHash::of_token(&token_from_entropy(&[5; 32])).to_config_string()
        )
    }

    fn full_text() -> String {
        format!(
            r#"
[server]
listen = "127.0.0.1:9000"
endpoint = "/connector/mcp"
allowed_hosts = ["gate.example.com"]
allowed_origins = ["https://app.example.com"]
max_request_bytes = 65536
request_timeout_ms = 20000
header_timeout_ms = 5000
idle_timeout_ms = 5000
max_connections = 16
kill_switch_file = "KILL"

[child]
command = ["./server", "--stdio"]
cwd = "work"
inherit_env = ["PATH", "HOME"]
restart = "always"
max_restarts = 3
restart_backoff_ms = 100
max_line_bytes = 1048576
startup_timeout_ms = 5000
shutdown_grace_ms = 1000
memory_mb = 256
cpu_seconds = 120
max_open_files = 128
max_file_mb = 50
[child.env]
MODE = "read"

[tools]
allow = ["*"]
deny = ["delete_*"]
read_only = true
read_patterns = ["get_*", "list_*"]
[[tools.rule]]
tool = "send_*"
max_string_len = 100
forbid_values = ["*://*"]

[limits]
requests_per_minute = 60
burst = 10
result_max_bytes = 65536
tool_result_prefix = "[tool output] "
max_inflight = 4
failed_auth_per_minute = 10

[audit]
path = "logs/audit.jsonl"
log_arguments = true
arguments_max_chars = 256

{}
[[token]]
id = "narrow"
hash = "{}"
scopes = ["tools:list"]
tools = ["get_*"]
"#,
            token_block(),
            TokenHash::of_token("x").to_config_string()
        )
    }

    #[test]
    fn a_complete_file_maps_onto_the_configuration() {
        let c = parse_config(&full_text()).unwrap();
        assert_eq!(c.server.listen.to_string(), "127.0.0.1:9000");
        assert_eq!(c.server.endpoint, "/connector/mcp");
        assert_eq!(c.server.max_connections, 16);
        assert_eq!(c.child.command, ["./server", "--stdio"]);
        assert_eq!(c.child.env, [("MODE".to_string(), "read".to_string())]);
        assert_eq!(c.child.limits.memory_mb, Some(256));
        assert!(c.policy.read_only && c.policy.rules.len() == 1 && c.policy.deny.len() == 1);
        assert_eq!(
            c.limits.tool_result_prefix.as_deref(),
            Some("[tool output] ")
        );
        assert!(c.audit.log_arguments);
        assert_eq!(c.authenticator.tokens().len(), 2);
    }

    #[test]
    fn a_minimal_file_is_enough() {
        let text = format!("[child]\ncommand = [\"server\"]\n\n{}", token_block());
        let c = parse_config(&text).unwrap();
        assert_eq!(c.server.listen.to_string(), "127.0.0.1:8787");
        assert!(!c.policy.read_only);
    }

    #[test]
    fn unknown_keys_are_errors_everywhere() {
        let text = full_text();
        for (needle, replacement, expect) in [
            (
                "[server]\n",
                "[server]\nlisten_on = 1\n",
                "server.listen_on: unknown key",
            ),
            (
                "[child.env]\nMODE = \"read\"",
                "[child.env]\nMODE = \"read\"\nBAD = 1",
                "child.env.BAD: expected a string",
            ),
            (
                "read_only = true",
                "read_only = true\nallw = []",
                "tools.allw: unknown key",
            ),
            (
                "[limits]\n",
                "[limits]\nburts = 1\n",
                "limits.burts: unknown key",
            ),
            (
                "[audit]\n",
                "[audit]\nfile = \"x\"\n",
                "audit.file: unknown key",
            ),
            (
                "id = \"narrow\"",
                "id = \"narrow\"\nadmin = true",
                "token[1].admin: unknown key",
            ),
            (
                "tool = \"send_*\"",
                "tool = \"send_*\"\nmax = 1",
                "tools.rule[0].max: unknown key",
            ),
        ] {
            let errors = parse_config(&text.replacen(needle, replacement, 1)).unwrap_err();
            assert!(
                errors.iter().any(|e| e.contains(expect)),
                "{expect} not in {errors:?}"
            );
        }
        let errors = parse_config(&format!("{text}\n[surprise]\nx = 1\n")).unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("surprise: unknown key")),
            "{errors:?}"
        );
    }

    #[test]
    fn wrong_types_are_errors() {
        let base = format!("[child]\ncommand = [\"s\"]\n{}", token_block());
        for (extra, expect) in [
            ("[server]\nlisten = 5\n", "server.listen: expected a string"),
            (
                "[server]\nmax_connections = \"8\"\n",
                "server.max_connections: expected an integer",
            ),
            (
                "[tools]\nread_only = \"yes\"\n",
                "tools.read_only: expected true or false",
            ),
            (
                "[tools]\nallow = \"*\"\n",
                "tools.allow: expected a list of strings",
            ),
            (
                "[tools]\nallow = [1]\n",
                "tools.allow: every item must be a string",
            ),
            ("server = 1\n", "server: expected a table"),
            (
                "tools = { rule = 1 }\n",
                "tools.rule: expected [[rule]] tables",
            ),
        ] {
            let errors = parse_config(&format!("{extra}{base}")).unwrap_err();
            assert!(
                errors.iter().any(|e| e.contains(expect)),
                "{expect} not in {errors:?}"
            );
        }
    }

    #[test]
    fn syntax_and_validation_errors_come_back_as_messages() {
        assert!(parse_config("[child").unwrap_err()[0].starts_with("line 1:"));
        let e = parse_config("").unwrap_err();
        assert!(
            e.iter().any(|m| m.starts_with("child.command"))
                && e.iter().any(|m| m.starts_with("token"))
        );
    }

    #[test]
    fn loading_resolves_relative_paths_against_the_file() {
        let dir = TempDir::new("cfg");
        let path = dir.write("gate.toml", &full_text());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let c = load(&path).unwrap();
        let base = dir.path().to_string_lossy().into_owned();
        assert_eq!(c.audit.path, format!("{base}/logs/audit.jsonl"));
        assert_eq!(c.server.kill_switch_file, Some(format!("{base}/KILL")));
        assert_eq!(c.child.cwd, Some(format!("{base}/work")));
        assert_eq!(c.child.command[0], format!("{base}/./server"));
        assert_eq!(c.child.command[1], "--stdio");
    }

    #[test]
    fn absolute_paths_stay_as_they_are() {
        assert_eq!(
            resolve(Path::new("/etc/gate"), "/var/log/a.jsonl"),
            "/var/log/a.jsonl"
        );
        assert_eq!(
            resolve(Path::new("/etc/gate"), "a.jsonl"),
            "/etc/gate/a.jsonl"
        );
    }

    #[test]
    fn a_file_that_others_can_write_is_refused() {
        let dir = TempDir::new("cfgperm");
        let path = dir.write("gate.toml", &full_text());
        for mode in [0o666, 0o664, 0o646] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let e = load(&path).unwrap_err();
            assert!(
                e[0].contains("can be written by other users"),
                "{mode:o}: {e:?}"
            );
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            load(&path).is_ok(),
            "readable by others is fine: the file holds only hashes"
        );
    }

    #[test]
    fn missing_and_oversized_files() {
        let dir = TempDir::new("cfgmiss");
        assert!(load(&dir.join("nope.toml")).unwrap_err()[0].contains("cannot read"));
        assert!(load(dir.path()).unwrap_err()[0].contains("not a file"));
        let big = dir.write("big.toml", &"#".repeat(toml::MAX_BYTES + 1));
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&big).unwrap_err()[0].contains("larger than"));
    }
}
