//! The command line of `mcp-remote-gate`.
//!
//! `run` serves the gateway, `check` validates a configuration and shows what it exposes, `tools`
//! asks the real server which tools it has and which of them the policy lets through, `token`
//! creates and hashes tokens, `selftest` proves the setup end to end against a bundled fake
//! server, and `init` prints an example configuration.

pub mod args;
mod check;
mod init;
mod selftest;
mod serve;
mod token;
mod tools;

use std::io::{BufRead, Write};
use std::path::Path;

use args::{FlagSpec, Parsed};
use gate_domain::config::Config;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Standard streams, injected so that commands can be tested.
pub struct Io<'a> {
    pub stdin: &'a mut dyn BufRead,
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

/// Exit status: the command did what it was asked.
pub const OK: i32 = 0;
/// A runtime failure: the gateway could not start, a self test failed.
pub const FAILED: i32 = 1;
/// The command line or the configuration is wrong.
pub const USAGE: i32 = 2;

const HELP: &str = "\
mcp-remote-gate: put a stdio MCP server behind an authenticated HTTP gateway

usage:
  mcp-remote-gate run --config gate.toml [--i-know-this-is-not-tls]
  mcp-remote-gate check --config gate.toml
  mcp-remote-gate tools --config gate.toml
  mcp-remote-gate token new [--id NAME] [--scopes tools:list,tools:call] [--tools PATTERNS]
  mcp-remote-gate token hash          (reads a token from standard input)
  mcp-remote-gate selftest
  mcp-remote-gate init                (prints an example gate.toml)
  mcp-remote-gate version

exit status: 0 ok, 1 failed at run time, 2 usage or configuration error
internal: mcp-remote-gate fake-mcp   (the bundled fake server used by selftest and the demo)
";

pub(crate) fn config_flag() -> [FlagSpec; 1] {
    [FlagSpec {
        name: "config",
        takes_value: true,
    }]
}

pub(crate) fn usage_error(io: &mut Io<'_>, message: &str) -> i32 {
    let _ = writeln!(io.err, "error: {message}\n\n{HELP}");
    USAGE
}

/// Loads the configuration named by `--config`; on failure prints every problem.
pub(crate) fn load_config(parsed: &Parsed, io: &mut Io<'_>) -> Result<Config, i32> {
    let Some(path) = parsed.value("config") else {
        return Err(usage_error(io, "--config is required"));
    };
    match gate_infra::config_file::load(Path::new(path)) {
        Ok(config) => Ok(config),
        Err(problems) => {
            let _ = writeln!(io.err, "the configuration {path} is not valid:");
            for p in problems {
                let _ = writeln!(io.err, "  {p}");
            }
            Err(USAGE)
        }
    }
}

pub fn run(args: &[String], io: &mut Io<'_>) -> i32 {
    let Some((command, rest)) = args.split_first() else {
        let _ = write!(io.out, "{HELP}");
        return USAGE;
    };
    match command.as_str() {
        "run" => serve::run(rest, io),
        "check" => check::run(rest, io),
        "tools" => tools::run(rest, io),
        "token" => token::run(rest, io),
        "selftest" => selftest::run(rest, io),
        "init" => init::run(rest, io),
        "version" | "--version" | "-V" => {
            let _ = writeln!(io.out, "mcp-remote-gate {VERSION}");
            OK
        }
        "help" | "--help" | "-h" => {
            let _ = write!(io.out, "{HELP}");
            OK
        }
        other => usage_error(io, &format!("unknown command {other}")),
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

    pub(crate) fn run_captured(args: &[&str], stdin: &str) -> (i32, String, String) {
        let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let mut input = stdin.as_bytes();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(
            &args,
            &mut Io {
                stdin: &mut input,
                out: &mut out,
                err: &mut err,
            },
        );
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn help_and_version() {
        let (code, out, _) = run_captured(&["help"], "");
        assert_eq!(code, OK);
        assert!(out.contains("usage:") && out.contains("token new"));
        let (code, out, _) = run_captured(&["version"], "");
        assert_eq!(
            (code, out.trim()),
            (OK, format!("mcp-remote-gate {VERSION}").as_str())
        );
        assert_eq!(run_captured(&["--version"], "").0, OK);
        assert_eq!(run_captured(&["-h"], "").0, OK);
    }

    #[test]
    fn no_command_and_unknown_commands_are_usage_errors() {
        let (code, out, _) = run_captured(&[], "");
        assert_eq!(code, USAGE);
        assert!(out.contains("usage:"));
        let (code, _, err) = run_captured(&["frobnicate"], "");
        assert_eq!(code, USAGE);
        assert!(err.contains("unknown command frobnicate"));
    }

    #[test]
    fn a_missing_config_flag_is_a_usage_error() {
        for cmd in ["run", "check", "tools"] {
            let (code, _, err) = run_captured(&[cmd], "");
            assert_eq!(code, USAGE, "{cmd}");
            assert!(err.contains("--config is required"));
        }
    }

    #[test]
    fn an_unreadable_config_is_reported() {
        let (code, _, err) = run_captured(&["check", "--config", "/nonexistent/gate.toml"], "");
        assert_eq!(code, USAGE);
        assert!(err.contains("is not valid") && err.contains("cannot read"));
    }
}
