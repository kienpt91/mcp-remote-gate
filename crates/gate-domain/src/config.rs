//! The validated configuration. The file format (TOML) is an adapter concern: the adapter reads
//! the file into a [`RawConfig`] of plain optional values and this module checks every value,
//! fills in the defaults and reports all problems at once.

use std::net::SocketAddr;

use crate::auth::{Authenticator, BadHash, Scope, TokenEntry, TokenHash, TokenId};
use crate::glob::Glob;
use crate::hostcheck::{loopback_hosts, normalize_host, normalize_origin, HostPolicy};
use crate::policy::{default_read_patterns, ArgRule, ToolPolicy};
use crate::restart::{RestartMode, RestartPolicy};

#[derive(Debug, Clone, Default)]
pub struct RawConfig {
    pub server: RawServer,
    pub child: RawChild,
    pub tools: RawTools,
    pub limits: RawLimits,
    pub audit: RawAudit,
    pub tokens: Vec<RawToken>,
}

#[derive(Debug, Clone, Default)]
pub struct RawServer {
    pub listen: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_hosts: Option<Vec<String>>,
    pub allowed_origins: Option<Vec<String>>,
    pub max_request_bytes: Option<i64>,
    pub request_timeout_ms: Option<i64>,
    pub header_timeout_ms: Option<i64>,
    pub idle_timeout_ms: Option<i64>,
    pub max_connections: Option<i64>,
    pub kill_switch_file: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RawChild {
    pub command: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub inherit_env: Option<Vec<String>>,
    pub restart: Option<String>,
    pub max_restarts: Option<i64>,
    pub restart_backoff_ms: Option<i64>,
    pub max_line_bytes: Option<i64>,
    pub startup_timeout_ms: Option<i64>,
    pub shutdown_grace_ms: Option<i64>,
    pub memory_mb: Option<i64>,
    pub cpu_seconds: Option<i64>,
    pub max_open_files: Option<i64>,
    pub max_file_mb: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct RawTools {
    pub allow: Option<Vec<String>>,
    pub deny: Option<Vec<String>>,
    pub read_only: Option<bool>,
    pub read_patterns: Option<Vec<String>>,
    pub rules: Vec<RawRule>,
}

#[derive(Debug, Clone, Default)]
pub struct RawRule {
    pub tool: Option<String>,
    pub max_arg_bytes: Option<i64>,
    pub max_string_len: Option<i64>,
    pub forbid_values: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct RawLimits {
    pub requests_per_minute: Option<i64>,
    pub burst: Option<i64>,
    pub result_max_bytes: Option<i64>,
    pub tool_result_prefix: Option<String>,
    pub max_inflight: Option<i64>,
    pub failed_auth_per_minute: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct RawAudit {
    pub path: Option<String>,
    pub log_arguments: Option<bool>,
    pub arguments_max_chars: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct RawToken {
    pub id: Option<String>,
    pub hash: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub tools: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub endpoint: String,
    pub hosts: HostPolicy,
    pub max_request_bytes: usize,
    pub request_timeout_ms: u64,
    pub header_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub max_connections: usize,
    pub kill_switch_file: Option<String>,
}

impl ServerConfig {
    /// Whether the gateway listens on a loopback address only.
    pub fn is_loopback(&self) -> bool {
        self.listen.ip().is_loopback()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChildLimits {
    pub memory_mb: Option<u64>,
    pub cpu_seconds: Option<u64>,
    pub max_open_files: Option<u64>,
    pub max_file_mb: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ChildConfig {
    pub command: Vec<String>,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub inherit_env: Vec<String>,
    pub restart: RestartPolicy,
    pub max_line_bytes: usize,
    pub startup_timeout_ms: u64,
    pub shutdown_grace_ms: u64,
    pub limits: ChildLimits,
}

#[derive(Debug, Clone)]
pub struct LimitsConfig {
    pub requests_per_minute: u32,
    pub burst: u32,
    pub result_max_bytes: Option<usize>,
    pub tool_result_prefix: Option<String>,
    pub max_inflight: usize,
    pub failed_auth_per_minute: u32,
}

#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub path: String,
    pub log_arguments: bool,
    pub arguments_max_chars: usize,
}

#[derive(Debug)]
pub struct Config {
    pub server: ServerConfig,
    pub child: ChildConfig,
    pub policy: ToolPolicy,
    pub limits: LimitsConfig,
    pub audit: AuditConfig,
    pub authenticator: Authenticator,
}

struct Problems(Vec<String>);

impl Problems {
    fn add(&mut self, path: &str, message: &str) {
        self.0.push(format!("{path}: {message}"));
    }

    fn int(&mut self, path: &str, value: Option<i64>, default: i64, min: i64, max: i64) -> i64 {
        match value {
            None => default,
            Some(v) if (min..=max).contains(&v) => v,
            Some(_) => {
                self.add(path, &format!("must be between {min} and {max}"));
                default
            }
        }
    }

    fn opt_int(&mut self, path: &str, value: Option<i64>, min: i64, max: i64) -> Option<i64> {
        value.map(|v| self.int(path, Some(v), min, min, max))
    }

    fn globs(&mut self, path: &str, patterns: &[String]) -> Vec<Glob> {
        let mut out = Vec::new();
        for (i, p) in patterns.iter().enumerate() {
            match Glob::new(p) {
                Ok(g) => out.push(g),
                Err(e) => self.add(&format!("{path}[{i}]"), &e.to_string()),
            }
        }
        out
    }
}

fn has_nul_or_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn valid_endpoint(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 128
        && !path.contains(['?', '#', ' ', '\\'])
        && !has_nul_or_control(path)
        && path.is_ascii()
}

impl Config {
    /// Validates `raw`; on failure returns every problem found, each prefixed by its key.
    pub fn build(raw: RawConfig) -> Result<Config, Vec<String>> {
        let mut p = Problems(Vec::new());
        let server = build_server(&mut p, &raw.server);
        let child = build_child(&mut p, &raw.child);
        let policy = build_policy(&mut p, &raw.tools);
        let limits = build_limits(&mut p, &raw.limits);
        let audit = build_audit(&mut p, &raw.audit);
        let tokens = build_tokens(&mut p, &raw.tokens);
        if !p.0.is_empty() {
            return Err(p.0);
        }
        Ok(Config {
            server,
            child,
            policy,
            limits,
            audit,
            authenticator: Authenticator::new(tokens),
        })
    }

    /// Settings that are valid but deserve a second look before going live.
    pub fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        if !self.server.is_loopback() {
            w.push(format!(
                "listening on {}, which is not a loopback address: the gateway has no TLS, put it behind a TLS-terminating proxy or on a private network",
                self.server.listen
            ));
        }
        let p = &self.policy;
        if p.allow.is_empty() && !p.read_only {
            w.push("no tool is allowed (allow is empty and read_only is off): the gateway will list no tools and refuse every call".into());
        }
        if !p.read_only && p.allow.iter().any(|g| g.as_str() == "*") && p.deny.is_empty() {
            w.push("every tool of the server is callable, including any that send, write or delete: set read_only = true or add a deny list".into());
        }
        if self.audit.log_arguments {
            w.push(
                "argument values are written to the audit log (redacted by heuristics only)".into(),
            );
        }
        if !self.server.hosts.origins().is_empty() {
            w.push("browser origins are allowed: the gateway sends no CORS headers, so only non-browser clients can use it".into());
        }
        w
    }
}

fn build_server(p: &mut Problems, raw: &RawServer) -> ServerConfig {
    let listen_text = raw.listen.as_deref().unwrap_or("127.0.0.1:8787");
    let listen = match listen_text.parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            p.add(
                "server.listen",
                "must be an IP address and a port such as 127.0.0.1:8787 (no host names)",
            );
            SocketAddr::from(([127, 0, 0, 1], 8787))
        }
    };
    let endpoint = raw.endpoint.clone().unwrap_or_else(|| "/mcp".to_string());
    if !valid_endpoint(&endpoint) {
        p.add(
            "server.endpoint",
            "must be an absolute path of printable ASCII without ?, # or spaces",
        );
    }
    let mut hosts: Vec<String> = Vec::new();
    match &raw.allowed_hosts {
        Some(list) => {
            for (i, h) in list.iter().enumerate() {
                match normalize_host(h) {
                    Some(n) => hosts.push(n),
                    None => p.add(
                        &format!("server.allowed_hosts[{i}]"),
                        "must be host or host:port",
                    ),
                }
            }
        }
        None if listen.ip().is_loopback() => hosts = loopback_hosts(listen),
        None => p.add(
            "server.allowed_hosts",
            "is required when the gateway does not listen on a loopback address",
        ),
    }
    let mut origins = Vec::new();
    for (i, o) in raw.allowed_origins.iter().flatten().enumerate() {
        match normalize_origin(o) {
            Some(n) => origins.push(n),
            None => p.add(
                &format!("server.allowed_origins[{i}]"),
                "must look like https://host[:port]",
            ),
        }
    }
    ServerConfig {
        listen,
        endpoint,
        hosts: HostPolicy::new(hosts, origins),
        max_request_bytes: p.int(
            "server.max_request_bytes",
            raw.max_request_bytes,
            1_048_576,
            1024,
            16 << 20,
        ) as usize,
        request_timeout_ms: p.int(
            "server.request_timeout_ms",
            raw.request_timeout_ms,
            30_000,
            100,
            600_000,
        ) as u64,
        header_timeout_ms: p.int(
            "server.header_timeout_ms",
            raw.header_timeout_ms,
            10_000,
            100,
            60_000,
        ) as u64,
        idle_timeout_ms: p.int(
            "server.idle_timeout_ms",
            raw.idle_timeout_ms,
            15_000,
            100,
            120_000,
        ) as u64,
        max_connections: p.int("server.max_connections", raw.max_connections, 64, 1, 1024) as usize,
        kill_switch_file: match &raw.kill_switch_file {
            Some(f) if f.is_empty() || has_nul_or_control(f) => {
                p.add("server.kill_switch_file", "must be a file path");
                None
            }
            other => other.clone(),
        },
    }
}

fn build_child(p: &mut Problems, raw: &RawChild) -> ChildConfig {
    let command = match &raw.command {
        Some(c)
            if !c.is_empty()
                && !c.iter().any(|a| a.contains('\0'))
                && !c.first().is_some_and(String::is_empty) =>
        {
            c.clone()
        }
        Some(_) => {
            p.add(
                "child.command",
                "must be a non-empty list of strings: the program and its arguments",
            );
            Vec::new()
        }
        None => {
            p.add(
                "child.command",
                "is required: the program and its arguments as a list",
            );
            Vec::new()
        }
    };
    for (name, value) in &raw.env {
        if !valid_env_name(name) {
            p.add(
                &format!("child.env.{name}"),
                "is not a valid environment variable name",
            );
        }
        if value.contains('\0') {
            p.add(&format!("child.env.{name}"), "must not contain NUL");
        }
    }
    let inherit_env = raw
        .inherit_env
        .clone()
        .unwrap_or_else(|| vec!["PATH".to_string()]);
    for (i, name) in inherit_env.iter().enumerate() {
        if !valid_env_name(name) {
            p.add(
                &format!("child.inherit_env[{i}]"),
                "is not a valid environment variable name",
            );
        }
    }
    if let Some(cwd) = &raw.cwd {
        if cwd.is_empty() || cwd.contains('\0') {
            p.add("child.cwd", "must be a directory path");
        }
    }
    let mode = match raw.restart.as_deref() {
        None => RestartMode::OnFailure,
        Some(text) => RestartMode::parse(text).unwrap_or_else(|| {
            p.add(
                "child.restart",
                "must be \"never\", \"on-failure\" or \"always\"",
            );
            RestartMode::OnFailure
        }),
    };
    let restart = RestartPolicy {
        mode,
        max_restarts: p.int("child.max_restarts", raw.max_restarts, 5, 0, 100) as u32,
        backoff_ms: p.int(
            "child.restart_backoff_ms",
            raw.restart_backoff_ms,
            500,
            10,
            60_000,
        ) as u64,
        max_backoff_ms: 30_000,
    };
    let limits = ChildLimits {
        memory_mb: p
            .opt_int("child.memory_mb", raw.memory_mb, 16, 1 << 20)
            .map(|v| v as u64),
        cpu_seconds: p
            .opt_int("child.cpu_seconds", raw.cpu_seconds, 1, 31_536_000)
            .map(|v| v as u64),
        max_open_files: p
            .opt_int("child.max_open_files", raw.max_open_files, 16, 1 << 20)
            .map(|v| v as u64),
        max_file_mb: p
            .opt_int("child.max_file_mb", raw.max_file_mb, 1, 1 << 20)
            .map(|v| v as u64),
    };
    ChildConfig {
        command,
        cwd: raw.cwd.clone(),
        env: raw.env.clone(),
        inherit_env,
        restart,
        max_line_bytes: p.int(
            "child.max_line_bytes",
            raw.max_line_bytes,
            4 << 20,
            4096,
            64 << 20,
        ) as usize,
        startup_timeout_ms: p.int(
            "child.startup_timeout_ms",
            raw.startup_timeout_ms,
            15_000,
            100,
            300_000,
        ) as u64,
        shutdown_grace_ms: p.int(
            "child.shutdown_grace_ms",
            raw.shutdown_grace_ms,
            3000,
            0,
            60_000,
        ) as u64,
        limits,
    }
}

fn build_policy(p: &mut Problems, raw: &RawTools) -> ToolPolicy {
    let allow = p.globs("tools.allow", raw.allow.as_deref().unwrap_or_default());
    let deny = p.globs("tools.deny", raw.deny.as_deref().unwrap_or_default());
    let read_patterns = match &raw.read_patterns {
        Some(list) => p.globs("tools.read_patterns", list),
        None => default_read_patterns(),
    };
    let mut rules = Vec::new();
    for (i, r) in raw.rules.iter().enumerate() {
        let at = format!("tools.rule[{i}]");
        let tool = match r.tool.as_deref().map(Glob::new) {
            Some(Ok(g)) => Some(g),
            Some(Err(e)) => {
                p.add(&format!("{at}.tool"), &e.to_string());
                None
            }
            None => {
                p.add(
                    &format!("{at}.tool"),
                    "is required: the tool name pattern the rule applies to",
                );
                None
            }
        };
        let max_arg_bytes = p
            .opt_int(&format!("{at}.max_arg_bytes"), r.max_arg_bytes, 2, 16 << 20)
            .map(|v| v as usize);
        let max_string_len = p
            .opt_int(
                &format!("{at}.max_string_len"),
                r.max_string_len,
                1,
                16 << 20,
            )
            .map(|v| v as usize);
        let forbid_values = p.globs(
            &format!("{at}.forbid_values"),
            r.forbid_values.as_deref().unwrap_or_default(),
        );
        if r.max_arg_bytes.is_none() && r.max_string_len.is_none() && forbid_values.is_empty() {
            p.add(
                &at,
                "sets no limit: give max_arg_bytes, max_string_len or forbid_values",
            );
        }
        if let Some(tool) = tool {
            rules.push(ArgRule {
                tool,
                max_arg_bytes,
                max_string_len,
                forbid_values,
            });
        }
    }
    ToolPolicy {
        allow,
        deny,
        read_only: raw.read_only.unwrap_or(false),
        read_patterns,
        rules,
    }
}

fn build_limits(p: &mut Problems, raw: &RawLimits) -> LimitsConfig {
    let prefix = match &raw.tool_result_prefix {
        Some(t) if t.chars().count() > 200 || t.chars().any(|c| c.is_control() && c != '\n') => {
            p.add(
                "limits.tool_result_prefix",
                "must be at most 200 characters without control characters",
            );
            None
        }
        other => other.clone(),
    };
    LimitsConfig {
        requests_per_minute: p.int(
            "limits.requests_per_minute",
            raw.requests_per_minute,
            120,
            1,
            100_000,
        ) as u32,
        burst: p.int("limits.burst", raw.burst, 20, 1, 10_000) as u32,
        result_max_bytes: p
            .opt_int(
                "limits.result_max_bytes",
                raw.result_max_bytes,
                1024,
                64 << 20,
            )
            .map(|v| v as usize),
        tool_result_prefix: prefix,
        max_inflight: p.int("limits.max_inflight", raw.max_inflight, 16, 1, 256) as usize,
        failed_auth_per_minute: p.int(
            "limits.failed_auth_per_minute",
            raw.failed_auth_per_minute,
            30,
            1,
            10_000,
        ) as u32,
    }
}

fn build_audit(p: &mut Problems, raw: &RawAudit) -> AuditConfig {
    let path = raw
        .path
        .clone()
        .unwrap_or_else(|| "audit.jsonl".to_string());
    if path.is_empty() || has_nul_or_control(&path) {
        p.add("audit.path", "must be a file path");
    }
    AuditConfig {
        path,
        log_arguments: raw.log_arguments.unwrap_or(false),
        arguments_max_chars: p.int(
            "audit.arguments_max_chars",
            raw.arguments_max_chars,
            512,
            16,
            8192,
        ) as usize,
    }
}

fn build_tokens(p: &mut Problems, raw: &[RawToken]) -> Vec<TokenEntry> {
    if raw.is_empty() {
        p.add(
            "token",
            "at least one [[token]] is required: create one with `mcp-remote-gate token new`",
        );
    }
    let mut out: Vec<TokenEntry> = Vec::new();
    for (i, t) in raw.iter().enumerate() {
        let at = format!("token[{i}]");
        let id = match t.id.as_deref().map(TokenId::new) {
            Some(Some(id)) => Some(id),
            Some(None) => {
                p.add(
                    &format!("{at}.id"),
                    "must be 1 to 64 characters of letters, digits, _, . or -",
                );
                None
            }
            None => {
                p.add(&format!("{at}.id"), "is required");
                None
            }
        };
        if let Some(id) = &id {
            if out.iter().any(|e| e.id == *id) {
                p.add(&format!("{at}.id"), "is used by another token");
            }
        }
        let hash = match t.hash.as_deref().map(TokenHash::parse) {
            Some(Ok(h)) => Some(h),
            Some(Err(BadHash)) => {
                p.add(
                    &format!("{at}.hash"),
                    "must be sha256: followed by 64 hex digits (see `mcp-remote-gate token new`)",
                );
                None
            }
            None => {
                p.add(&format!("{at}.hash"), "is required");
                None
            }
        };
        let scopes = match &t.scopes {
            None => vec![Scope::ToolsList, Scope::ToolsCall],
            Some(list) => {
                let mut scopes = Vec::new();
                for (j, s) in list.iter().enumerate() {
                    match Scope::parse(s) {
                        Some(scope) if !scopes.contains(&scope) => scopes.push(scope),
                        Some(_) => {}
                        None => p.add(
                            &format!("{at}.scopes[{j}]"),
                            "must be \"tools:list\" or \"tools:call\"",
                        ),
                    }
                }
                scopes
            }
        };
        let tools = t
            .tools
            .as_ref()
            .map(|list| p.globs(&format!("{at}.tools"), list));
        if let (Some(id), Some(hash)) = (id, hash) {
            if out.iter().any(|e| e.hash == hash) {
                p.add(
                    &format!("{at}.hash"),
                    "is the same as the hash of another token",
                );
            }
            out.push(TokenEntry {
                id,
                hash,
                scopes,
                tools,
            });
        }
    }
    out
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
    use crate::hostcheck::HostError;

    fn hash(seed: &str) -> String {
        TokenHash::of_token(seed).to_config_string()
    }

    fn minimal() -> RawConfig {
        RawConfig {
            child: RawChild {
                command: Some(vec!["server".into(), "--stdio".into()]),
                ..Default::default()
            },
            tokens: vec![RawToken {
                id: Some("desktop".into()),
                hash: Some(hash("a")),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn problems(raw: RawConfig) -> Vec<String> {
        Config::build(raw).unwrap_err()
    }

    #[test]
    fn a_minimal_config_gets_safe_defaults() {
        let c = Config::build(minimal()).unwrap();
        assert_eq!(c.server.listen.to_string(), "127.0.0.1:8787");
        assert!(c.server.is_loopback());
        assert_eq!(c.server.endpoint, "/mcp");
        assert_eq!(c.server.max_request_bytes, 1_048_576);
        assert_eq!(c.server.hosts.hosts().len(), 3);
        assert_eq!(c.server.hosts.check_host(Some("localhost:8787")), Ok(()));
        assert_eq!(
            c.server.hosts.check_origin(Some("http://localhost:8787")),
            Err(HostError::NotAllowed)
        );
        assert!(!c.policy.read_only && c.policy.allow.is_empty() && c.policy.deny.is_empty());
        assert_eq!(c.child.inherit_env, vec!["PATH".to_string()]);
        assert_eq!(c.child.restart.mode, RestartMode::OnFailure);
        assert_eq!(c.child.limits, ChildLimits::default());
        assert_eq!(
            (
                c.limits.requests_per_minute,
                c.limits.burst,
                c.limits.max_inflight
            ),
            (120, 20, 16)
        );
        assert_eq!(c.audit.path, "audit.jsonl");
        assert!(!c.audit.log_arguments);
        assert_eq!(c.authenticator.tokens().len(), 1);
        assert_eq!(
            c.authenticator.tokens()[0].scopes,
            vec![Scope::ToolsList, Scope::ToolsCall]
        );
        assert!(c.server.kill_switch_file.is_none());
    }

    #[test]
    fn everything_set_explicitly() {
        let mut raw = minimal();
        raw.server = RawServer {
            listen: Some("[::1]:9000".into()),
            endpoint: Some("/connector/mcp".into()),
            allowed_hosts: Some(vec!["Mcp.Example.com".into()]),
            allowed_origins: Some(vec!["https://app.example.com".into()]),
            max_request_bytes: Some(4096),
            request_timeout_ms: Some(5000),
            header_timeout_ms: Some(2000),
            idle_timeout_ms: Some(1000),
            max_connections: Some(8),
            kill_switch_file: Some("/run/gate/KILL".into()),
        };
        raw.child = RawChild {
            command: Some(vec!["/usr/bin/node".into(), "wa.js".into()]),
            cwd: Some("/srv/wa".into()),
            env: vec![("WA_MODE".into(), "ro".into())],
            inherit_env: Some(vec!["PATH".into(), "HOME".into()]),
            restart: Some("always".into()),
            max_restarts: Some(2),
            restart_backoff_ms: Some(50),
            max_line_bytes: Some(8192),
            startup_timeout_ms: Some(1000),
            shutdown_grace_ms: Some(0),
            memory_mb: Some(512),
            cpu_seconds: Some(60),
            max_open_files: Some(64),
            max_file_mb: Some(10),
        };
        raw.tools = RawTools {
            allow: Some(vec!["*".into()]),
            deny: Some(vec!["send_*".into()]),
            read_only: Some(true),
            read_patterns: Some(vec!["get_*".into()]),
            rules: vec![RawRule {
                tool: Some("send_*".into()),
                max_arg_bytes: Some(100),
                max_string_len: Some(10),
                forbid_values: Some(vec!["*x*".into()]),
            }],
        };
        raw.limits = RawLimits {
            requests_per_minute: Some(10),
            burst: Some(2),
            result_max_bytes: Some(2048),
            tool_result_prefix: Some("[output] ".into()),
            max_inflight: Some(4),
            failed_auth_per_minute: Some(5),
        };
        raw.audit = RawAudit {
            path: Some("/var/log/gate.jsonl".into()),
            log_arguments: Some(true),
            arguments_max_chars: Some(64),
        };
        raw.tokens[0].scopes = Some(vec!["tools:list".into()]);
        raw.tokens[0].tools = Some(vec!["get_*".into()]);
        let c = Config::build(raw).unwrap();
        assert!(c.server.is_loopback());
        assert_eq!(c.server.hosts.hosts(), ["mcp.example.com".to_string()]);
        assert_eq!(c.server.hosts.origins().len(), 1);
        assert_eq!(c.child.restart.mode, RestartMode::Always);
        assert_eq!(
            c.child.limits,
            ChildLimits {
                memory_mb: Some(512),
                cpu_seconds: Some(60),
                max_open_files: Some(64),
                max_file_mb: Some(10)
            }
        );
        assert!(c.policy.read_only && c.policy.rules.len() == 1);
        assert_eq!(c.limits.result_max_bytes, Some(2048));
        assert!(c.audit.log_arguments);
        assert_eq!(c.authenticator.tokens()[0].scopes, vec![Scope::ToolsList]);
        assert!(c.authenticator.tokens()[0].tools.is_some());
    }

    #[test]
    fn missing_required_values() {
        let p = problems(RawConfig::default());
        assert!(p.iter().any(|m| m.starts_with("child.command:")));
        assert!(p.iter().any(|m| m.starts_with("token:")));
    }

    #[test]
    fn every_problem_is_reported_with_its_key() {
        let mut raw = minimal();
        raw.server.listen = Some("localhost:8787".into());
        raw.server.endpoint = Some("mcp".into());
        raw.server.max_request_bytes = Some(5);
        raw.server.allowed_origins = Some(vec!["nonsense".into()]);
        raw.child.restart = Some("sometimes".into());
        raw.child.env = vec![("1BAD".into(), "x".into()), ("OK".into(), "a\0b".into())];
        raw.tools.allow = Some(vec!["".into()]);
        raw.tools.rules = vec![RawRule::default()];
        raw.limits.burst = Some(0);
        raw.audit.path = Some(String::new());
        raw.tokens.push(RawToken {
            id: Some("bad id".into()),
            hash: Some("md5:00".into()),
            scopes: Some(vec!["admin".into()]),
            tools: None,
        });
        let p = problems(raw);
        for key in [
            "server.listen",
            "server.endpoint",
            "server.max_request_bytes",
            "server.allowed_origins[0]",
            "child.restart",
            "child.env.1BAD",
            "child.env.OK",
            "tools.allow[0]",
            "tools.rule[0].tool",
            "limits.burst",
            "audit.path",
            "token[1].id",
            "token[1].hash",
            "token[1].scopes[0]",
        ] {
            assert!(
                p.iter().any(|m| m.starts_with(key)),
                "{key} missing in {p:#?}"
            );
        }
    }

    #[test]
    fn a_non_loopback_listener_needs_explicit_hosts() {
        let mut raw = minimal();
        raw.server.listen = Some("0.0.0.0:8787".into());
        assert!(problems(raw.clone())
            .iter()
            .any(|m| m.starts_with("server.allowed_hosts")));
        raw.server.allowed_hosts = Some(vec!["gate.example.com".into()]);
        let c = Config::build(raw).unwrap();
        assert!(!c.server.is_loopback());
        assert!(c.warnings().iter().any(|w| w.contains("no TLS")));
    }

    #[test]
    fn duplicate_tokens_are_refused() {
        let mut raw = minimal();
        raw.tokens.push(RawToken {
            id: Some("desktop".into()),
            hash: Some(hash("b")),
            ..Default::default()
        });
        assert!(problems(raw.clone())
            .iter()
            .any(|m| m.contains("used by another token")));
        raw.tokens[1].id = Some("other".into());
        raw.tokens[1].hash = Some(hash("a"));
        assert!(problems(raw).iter().any(|m| m.contains("same as the hash")));
    }

    #[test]
    fn rules_need_a_limit_and_a_tool() {
        let mut raw = minimal();
        raw.tools.rules = vec![RawRule {
            tool: Some("send_*".into()),
            ..Default::default()
        }];
        assert!(problems(raw).iter().any(|m| m.contains("sets no limit")));
    }

    #[test]
    fn child_commands_are_checked() {
        for bad in [
            vec![],
            vec![String::new()],
            vec!["a".to_string(), "b\0".to_string()],
        ] {
            let mut raw = minimal();
            raw.child.command = Some(bad);
            assert!(problems(raw).iter().any(|m| m.starts_with("child.command")));
        }
    }

    #[test]
    fn warnings() {
        let c = Config::build(minimal()).unwrap();
        assert!(c
            .warnings()
            .iter()
            .any(|w| w.contains("no tool is allowed")));
        let mut raw = minimal();
        raw.tools.allow = Some(vec!["*".into()]);
        raw.audit.log_arguments = Some(true);
        raw.server.allowed_origins = Some(vec!["https://a.example".into()]);
        let w = Config::build(raw).unwrap().warnings();
        assert!(w.iter().any(|w| w.contains("every tool")));
        assert!(w.iter().any(|w| w.contains("argument values")));
        assert!(w.iter().any(|w| w.contains("CORS")));
        let mut raw = minimal();
        raw.tools.allow = Some(vec!["*".into()]);
        raw.tools.read_only = Some(true);
        assert!(Config::build(raw).unwrap().warnings().is_empty());
    }

    #[test]
    fn the_prefix_may_contain_a_newline_but_no_other_control_character() {
        let mut raw = minimal();
        raw.limits.tool_result_prefix = Some("[output]\n".into());
        assert!(Config::build(raw.clone()).is_ok());
        raw.limits.tool_result_prefix = Some("x\u{1b}[2J".into());
        assert!(problems(raw.clone())
            .iter()
            .any(|m| m.starts_with("limits.tool_result_prefix")));
        raw.limits.tool_result_prefix = Some("x".repeat(201));
        assert!(problems(raw)
            .iter()
            .any(|m| m.starts_with("limits.tool_result_prefix")));
    }

    #[test]
    fn out_of_range_numbers() {
        let mut raw = minimal();
        raw.server.max_connections = Some(0);
        raw.child.memory_mb = Some(1);
        raw.child.max_restarts = Some(-1);
        raw.limits.result_max_bytes = Some(10);
        let p = problems(raw);
        assert_eq!(p.len(), 4, "{p:?}");
    }
}
