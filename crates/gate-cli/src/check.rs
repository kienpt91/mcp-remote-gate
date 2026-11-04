use gate_domain::config::Config;
use gate_domain::glob::Glob;

use crate::args::parse;
use crate::{config_flag, load_config, usage_error, Io, OK};

fn patterns(list: &[Glob]) -> String {
    if list.is_empty() {
        "none".to_string()
    } else {
        list.iter().map(Glob::as_str).collect::<Vec<_>>().join(", ")
    }
}

/// What the configuration exposes, as text.
pub fn describe(config: &Config, path: &str) -> String {
    let mut out = String::new();
    let mut line = |text: String| {
        out.push_str(&text);
        out.push('\n');
    };
    let s = &config.server;
    line(format!("configuration {path}: valid"));
    line(format!(
        "listen:      {}{}",
        s.listen,
        if s.is_loopback() {
            " (loopback)"
        } else {
            " (NOT loopback, no TLS)"
        }
    ));
    line(format!("endpoint:    {}", s.endpoint));
    line(format!("hosts:       {}", s.hosts.hosts().join(", ")));
    line(format!(
        "origins:     {}",
        if s.hosts.origins().is_empty() {
            "none (any request with an Origin header is refused)".to_string()
        } else {
            s.hosts.origins().join(", ")
        }
    ));
    line(format!(
        "kill switch: {}",
        s.kill_switch_file.as_deref().map_or(
            "signals only (SIGUSR1 on, SIGUSR2 off)".to_string(),
            |f| format!("file {f}, and signals SIGUSR1 / SIGUSR2")
        )
    ));
    let c = &config.child;
    line(format!(
        "child:       {} ({} argument(s), restart {:?}, up to {} restarts)",
        c.command.first().map_or("", String::as_str),
        c.command.len().saturating_sub(1),
        c.restart.mode,
        c.restart.max_restarts
    ));
    line(format!(
        "child env:   inherits {}; sets {}",
        c.inherit_env.join(", "),
        if c.env.is_empty() {
            "nothing".to_string()
        } else {
            c.env
                .iter()
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        }
    ));
    let p = &config.policy;
    line(format!("tools:       read_only = {}", p.read_only));
    line(format!("  allow:     {}", patterns(&p.allow)));
    line(format!("  deny:      {}", patterns(&p.deny)));
    if p.read_only {
        line(format!("  reads:     {}", patterns(&p.read_patterns)));
    }
    line(format!("  arg rules: {}", p.rules.len()));
    let l = &config.limits;
    line(format!("limits:      {} requests/min per token (burst {}), {} bytes per request, {} calls in flight", l.requests_per_minute, l.burst, s.max_request_bytes, l.max_inflight));
    line(format!(
        "results:     {}{}",
        l.result_max_bytes
            .map_or("not capped".to_string(), |n| format!("capped at {n} bytes")),
        l.tool_result_prefix
            .as_deref()
            .map_or(String::new(), |p| format!(", prefixed with {p:?}"))
    ));
    line(format!(
        "audit:       {} ({})",
        config.audit.path,
        if config.audit.log_arguments {
            "argument values logged, redacted"
        } else {
            "argument values not logged"
        }
    ));
    for t in config.authenticator.tokens() {
        let scopes = t
            .scopes
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let narrow = t
            .tools
            .as_ref()
            .map_or(String::new(), |g| format!(", limited to {}", patterns(g)));
        line(format!("token:       {} ({scopes}{narrow})", t.id.as_str()));
    }
    for w in config.warnings() {
        line(format!("warning:     {w}"));
    }
    out
}

pub fn run(args: &[String], io: &mut Io<'_>) -> i32 {
    let parsed = match parse(args, &config_flag()) {
        Ok(p) if p.positional.is_empty() => p,
        Ok(_) => return usage_error(io, "check takes only --config"),
        Err(e) => return usage_error(io, &e),
    };
    let config = match load_config(&parsed, io) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let _ = io
        .out
        .write_all(describe(&config, parsed.value("config").unwrap_or("")).as_bytes());
    OK
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
    use crate::init::EXAMPLE;
    use crate::tests::run_captured;
    use gate_infra::testutil::TempDir;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_description_says_what_is_exposed() {
        let c = gate_infra::config_file::parse_config(EXAMPLE).unwrap();
        let text = describe(&c, "gate.toml");
        for expected in [
            "listen:      127.0.0.1:8787 (loopback)",
            "read_only = true",
            "allow:     *",
            "reads:     get_*",
            "token:       desktop (tools:list, tools:call)",
            "argument values not logged",
            "origins:     none",
        ] {
            assert!(text.contains(expected), "{expected} not in\n{text}");
        }
        assert!(!text.contains("warning:"));
    }

    #[test]
    fn warnings_are_shown() {
        let text = EXAMPLE.replace("read_only = true", "read_only = false");
        let c = gate_infra::config_file::parse_config(&text).unwrap();
        assert!(describe(&c, "x").contains("warning:     every tool"));
    }

    #[test]
    fn check_reads_the_file_and_reports_problems() {
        let dir = TempDir::new("check");
        let good = dir.write("gate.toml", EXAMPLE);
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (code, out, _) = run_captured(&["check", "--config", good.to_str().unwrap()], "");
        assert_eq!(code, OK);
        assert!(out.contains("valid"));
        let bad = dir.write("bad.toml", "[server]\nlisten = \"nope\"\n");
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (code, _, err) = run_captured(&["check", "--config", bad.to_str().unwrap()], "");
        assert_eq!(code, crate::USAGE);
        assert!(
            err.contains("server.listen") && err.contains("child.command") && err.contains("token"),
            "{err}"
        );
        assert_eq!(
            run_captured(&["check", "--config", "a", "b"], "").0,
            crate::USAGE
        );
    }
}
