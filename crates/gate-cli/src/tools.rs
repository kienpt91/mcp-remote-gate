use gate_app::upstream::{UpstreamError, UpstreamPort};
use gate_domain::json::Value;
use gate_domain::policy::Decision;
use gate_domain::sanitize::escape_control;
use gate_infra::runtime::{start_upstream, RunOptions};

use crate::args::parse;
use crate::{config_flag, load_config, usage_error, Io, FAILED, OK};

const MAX_PAGES: usize = 20;

/// The tool names the server lists, following `nextCursor` for a bounded number of pages.
fn list_all(upstream: &dyn UpstreamPort, timeout_ms: u64) -> Result<Vec<String>, UpstreamError> {
    let mut names = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let params = cursor
            .as_ref()
            .map(|c| Value::object([("cursor", Value::str(c))]));
        let page = upstream.request("tools/list", params, timeout_ms)?;
        if let Some(tools) = page.get("tools").and_then(Value::as_array) {
            names.extend(
                tools
                    .iter()
                    .filter_map(|t| t.get("name").and_then(Value::as_str))
                    .map(str::to_string),
            );
        }
        match page.get("nextCursor").and_then(Value::as_str) {
            Some(next) if !next.is_empty() => cursor = Some(next.to_string()),
            _ => break,
        }
    }
    Ok(names)
}

pub fn run(args: &[String], io: &mut Io<'_>) -> i32 {
    let parsed = match parse(args, &config_flag()) {
        Ok(p) if p.positional.is_empty() => p,
        Ok(_) => return usage_error(io, "tools takes only --config"),
        Err(e) => return usage_error(io, &e),
    };
    let config = match load_config(&parsed, io) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let opts = RunOptions {
        allow_non_loopback: false,
        use_signals: false,
        gate_version: crate::VERSION.to_string(),
        logger: None,
    };
    let upstream = match start_upstream(&config, &opts) {
        Ok(u) => u,
        Err(message) => {
            let _ = writeln!(io.err, "error: {message}");
            return FAILED;
        }
    };
    let result = list_all(upstream.as_ref(), config.server.request_timeout_ms);
    let info = upstream.info();
    upstream.shutdown();
    let names = match result {
        Ok(n) => n,
        Err(e) => {
            let _ = writeln!(io.err, "error: the server did not list its tools: {e:?}");
            return FAILED;
        }
    };
    if let Ok(info) = info {
        let _ = writeln!(
            io.out,
            "server: {} {} (protocol {})",
            escape_control(&info.server_name, 64),
            escape_control(&info.server_version, 32),
            info.protocol_version
        );
    }
    let _ = writeln!(
        io.out,
        "policy: read_only = {}, allow = {}, deny = {}",
        config.policy.read_only,
        config.policy.allow.len(),
        config.policy.deny.len()
    );
    let width = names
        .iter()
        .map(|n| n.chars().count().min(48))
        .max()
        .unwrap_or(4)
        .max(4);
    let mut exposed = 0;
    for name in &names {
        let shown = escape_control(name, 48);
        match config.policy.decide(name) {
            Decision::Allow => {
                exposed += 1;
                let _ = writeln!(io.out, "  {shown:<width$}  exposed");
            }
            Decision::Deny(reason) => {
                let _ = writeln!(io.out, "  {shown:<width$}  blocked ({})", reason.code());
            }
        }
    }
    let _ = writeln!(
        io.out,
        "{} tools, {exposed} exposed, {} blocked",
        names.len(),
        names.len() - exposed
    );
    OK
}
