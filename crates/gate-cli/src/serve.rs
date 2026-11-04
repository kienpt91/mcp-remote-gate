use std::sync::Arc;
use std::time::Duration;

use gate_app::ports::{Level, Logger};
use gate_infra::runtime::{start, RunOptions};
use gate_infra::system::{StderrLogger, SystemClock};

use crate::args::{parse, FlagSpec};
use crate::{load_config, usage_error, Io, FAILED, OK, USAGE};

pub fn run(args: &[String], io: &mut Io<'_>) -> i32 {
    let spec = [
        FlagSpec {
            name: "config",
            takes_value: true,
        },
        FlagSpec {
            name: "i-know-this-is-not-tls",
            takes_value: false,
        },
    ];
    let parsed = match parse(args, &spec) {
        Ok(p) if p.positional.is_empty() => p,
        Ok(_) => return usage_error(io, "run takes only options"),
        Err(e) => return usage_error(io, &e),
    };
    let config = match load_config(&parsed, io) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let opts = RunOptions {
        allow_non_loopback: parsed.has("i-know-this-is-not-tls"),
        use_signals: true,
        gate_version: crate::VERSION.to_string(),
        logger: None,
    };
    if let Err(message) =
        gate_infra::runtime::check_listen_address(&config, opts.allow_non_loopback)
    {
        let _ = writeln!(io.err, "error: {message}");
        return USAGE;
    }
    let log = StderrLogger::new(Arc::new(SystemClock::new()));
    for w in config.warnings() {
        log.log(Level::Warn, &w);
    }
    if let Err(e) = gate_sys::install_signal_flags() {
        let _ = writeln!(io.err, "error: cannot install signal handlers: {e}");
        return FAILED;
    }
    let gate = match start(config, &opts) {
        Ok(g) => g,
        Err(message) => {
            let _ = writeln!(io.err, "error: {message}");
            return FAILED;
        }
    };
    log.log(
        Level::Info,
        &format!(
            "mcp-remote-gate {} ready on {}",
            crate::VERSION,
            gate.local_addr()
        ),
    );
    while !gate_sys::shutdown_requested() {
        std::thread::sleep(Duration::from_millis(100));
    }
    log.log(
        Level::Info,
        "shutting down: finishing requests in progress, then stopping the upstream server",
    );
    let cut = gate.stop(Duration::from_secs(5));
    if cut > 0 {
        log.log(
            Level::Warn,
            &format!("{cut} connection(s) were still open at the end of the grace period"),
        );
    }
    OK
}
