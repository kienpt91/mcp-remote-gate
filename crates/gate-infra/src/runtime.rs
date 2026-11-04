//! Putting the parts together: opening the audit log, starting the upstream server, building
//! the gateway and serving it over HTTP.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use gate_app::gateway::{Gateway, GatewayConfig, Ports};
use gate_app::ports::{AuditSink, ChildSpawner, Clock, KillSwitch, Logger};
use gate_app::upstream::{StatsSnapshot, StdioUpstream, UpstreamPort, UpstreamSettings};
use gate_domain::config::Config;

use crate::audit_file::FileAudit;
use crate::child::ProcessSpawner;
use crate::http::{Handler, HttpLimits, HttpServer, Preflight};
use crate::system::{FileKillSwitch, StderrLogger, SystemClock};

#[derive(Clone)]
pub struct RunOptions {
    /// Allow a listen address that is not a loopback address (`--i-know-this-is-not-tls`).
    pub allow_non_loopback: bool,
    /// React to SIGTERM, SIGINT, SIGUSR1 and SIGUSR2 (only the real program does).
    pub use_signals: bool,
    pub gate_version: String,
    /// Where diagnostics go; standard error when `None`.
    pub logger: Option<Arc<dyn Logger>>,
}

pub struct RunningGate {
    server: HttpServer,
    upstream: Arc<StdioUpstream>,
}

impl RunningGate {
    pub fn local_addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    pub fn upstream_stats(&self) -> StatsSnapshot {
        self.upstream.stats()
    }

    pub fn upstream_status(&self) -> String {
        self.upstream.status()
    }

    /// Stops accepting requests, lets those in progress finish for up to `drain`, then stops the
    /// upstream server and its process group. Returns the number of connections that were cut.
    pub fn stop(self, drain: Duration) -> usize {
        let left = self.server.stop(drain);
        self.upstream.shutdown();
        left
    }
}

/// The error text when the listen address is not allowed.
pub fn check_listen_address(config: &Config, allow_non_loopback: bool) -> Result<(), String> {
    if config.server.is_loopback() || allow_non_loopback {
        return Ok(());
    }
    Err(format!(
        "refusing to listen on {}: it is not a loopback address and the gateway has no TLS. Put it behind a reverse proxy or tunnel that terminates TLS and listen on 127.0.0.1, or pass --i-know-this-is-not-tls if the network is private",
        config.server.listen
    ))
}

fn upstream_settings(config: &Config, gate_version: &str) -> UpstreamSettings {
    UpstreamSettings {
        restart: config.child.restart,
        startup_timeout_ms: config.child.startup_timeout_ms,
        max_inflight: config.limits.max_inflight,
        gate_version: gate_version.to_string(),
    }
}

/// Opens the audit log and reports a file whose mode had to be tightened.
pub fn open_audit(path: &str, log: &dyn Logger) -> Result<Arc<dyn AuditSink>, String> {
    let audit = FileAudit::open(std::path::Path::new(path))
        .map_err(|e| format!("cannot open the audit log {path}: {e}"))?;
    if let Some(mode) = audit.tightened_from() {
        log.log(
            gate_app::ports::Level::Warn,
            &format!("the audit file {path} had mode {mode:03o}; it was changed to 600"),
        );
    }
    Ok(Arc::new(audit))
}

/// Starts only the upstream server (for `tools`).
pub fn start_upstream(config: &Config, opts: &RunOptions) -> Result<Arc<StdioUpstream>, String> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let log: Arc<dyn Logger> = opts
        .logger
        .clone()
        .unwrap_or_else(|| Arc::new(StderrLogger::new(Arc::clone(&clock))));
    let spawner: Arc<dyn ChildSpawner> =
        Arc::new(ProcessSpawner::new(config.child.clone(), Arc::clone(&log)));
    StdioUpstream::start(
        upstream_settings(config, &opts.gate_version),
        spawner,
        clock,
        log,
    )
    .map(Arc::new)
    .map_err(|e| format!("the upstream server did not start: {e}"))
}

pub fn start(config: Config, opts: &RunOptions) -> Result<RunningGate, String> {
    check_listen_address(&config, opts.allow_non_loopback)?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let log: Arc<dyn Logger> = opts
        .logger
        .clone()
        .unwrap_or_else(|| Arc::new(StderrLogger::new(Arc::clone(&clock))));
    let audit = open_audit(&config.audit.path, log.as_ref())?;
    let kill: Arc<dyn KillSwitch> = Arc::new(FileKillSwitch::new(
        config.server.kill_switch_file.as_ref().map(PathBuf::from),
        opts.use_signals,
    ));
    let upstream = start_upstream(&config, opts)?;
    let upstream_port: Arc<dyn UpstreamPort> = upstream.clone();
    let gateway_config = GatewayConfig::from_config(&config, &opts.gate_version);
    let http_limits = HttpLimits::new(
        config.server.max_request_bytes,
        config.server.header_timeout_ms,
        config.server.idle_timeout_ms,
        config.server.max_connections,
    );
    let listen = config.server.listen;
    let Config {
        authenticator,
        policy,
        ..
    } = config;
    let gateway = Arc::new(Gateway::new(
        gateway_config,
        authenticator,
        policy,
        Ports {
            upstream: upstream_port,
            clock,
            audit,
            kill,
            log: Arc::clone(&log),
        },
    ));
    let listener = match TcpListener::bind(listen) {
        Ok(l) => l,
        Err(e) => {
            upstream.shutdown();
            return Err(format!("cannot listen on {listen}: {e}"));
        }
    };
    let early = Arc::clone(&gateway);
    let handler: Handler = Arc::new(move |request| gateway.handle(request));
    let preflight: Preflight = Arc::new(move |request| early.preflight(request));
    let server = match HttpServer::start_with_preflight(
        listener,
        http_limits,
        handler,
        Some(preflight),
        Arc::clone(&log),
    ) {
        Ok(s) => s,
        Err(e) => {
            upstream.shutdown();
            return Err(format!("cannot start the HTTP server: {e}"));
        }
    };
    log.log(
        gate_app::ports::Level::Info,
        &format!("listening on {}", server.local_addr()),
    );
    Ok(RunningGate { server, upstream })
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
    use crate::config_file::parse_config;
    use gate_domain::auth::{token_from_entropy, TokenHash};

    fn config(listen: &str) -> Config {
        let hash = TokenHash::of_token(&token_from_entropy(&[1; 32])).to_config_string();
        parse_config(&format!(
            "[server]\nlisten = \"{listen}\"\nallowed_hosts = [\"gate.example.com\"]\n[child]\ncommand = [\"x\"]\n[[token]]\nid = \"t\"\nhash = \"{hash}\"\n"
        ))
        .unwrap()
    }

    #[test]
    fn loopback_addresses_need_no_flag() {
        for listen in ["127.0.0.1:8787", "[::1]:8787", "127.0.0.2:1"] {
            assert!(
                check_listen_address(&config(listen), false).is_ok(),
                "{listen}"
            );
        }
    }

    #[test]
    fn other_addresses_are_refused_without_the_flag() {
        for listen in [
            "0.0.0.0:8787",
            "192.168.1.5:8787",
            "[::]:8787",
            "10.0.0.1:80",
        ] {
            let e = check_listen_address(&config(listen), false).unwrap_err();
            assert!(
                e.contains("--i-know-this-is-not-tls") && e.contains("TLS"),
                "{e}"
            );
            assert!(check_listen_address(&config(listen), true).is_ok());
        }
    }

    #[test]
    fn a_missing_program_stops_the_start_before_anything_is_bound() {
        let dir = crate::testutil::TempDir::new("rt");
        let mut c = config("127.0.0.1:0");
        c.audit.path = dir.join("audit.jsonl").to_string_lossy().into_owned();
        c.child.command = vec!["/nonexistent/program".into()];
        let opts = RunOptions {
            allow_non_loopback: false,
            use_signals: false,
            gate_version: "t".into(),
            logger: Some(Arc::new(gate_app::testing::VecLogger::default())),
        };
        let e = start(c, &opts).err().unwrap();
        assert!(e.contains("did not start"), "{e}");
    }

    #[test]
    fn a_loose_audit_file_is_tightened_and_reported() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::testutil::TempDir::new("rt-mode");
        let path = dir.write("audit.jsonl", "");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        let log = gate_app::testing::VecLogger::default();
        open_audit(path.to_str().unwrap(), &log).unwrap();
        assert!(
            log.contains("had mode 664") && log.contains("changed to 600"),
            "{:?}",
            log.lines()
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let quiet = gate_app::testing::VecLogger::default();
        open_audit(path.to_str().unwrap(), &quiet).unwrap();
        assert!(quiet.lines().is_empty());
    }

    #[test]
    fn an_audit_path_that_is_a_symbolic_link_stops_the_start() {
        let dir = crate::testutil::TempDir::new("rt-link");
        let target = dir.write("target.log", "");
        let link = dir.join("audit.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let log = gate_app::testing::VecLogger::default();
        let e = open_audit(link.to_str().unwrap(), &log).err().unwrap();
        assert!(e.contains("cannot open the audit log"), "{e}");
    }

    #[test]
    fn an_audit_log_that_cannot_be_opened_stops_the_start() {
        let mut c = config("127.0.0.1:0");
        c.audit.path = "/nonexistent-dir-for-gate-tests/audit.jsonl".into();
        let opts = RunOptions {
            allow_non_loopback: false,
            use_signals: false,
            gate_version: "t".into(),
            logger: Some(Arc::new(gate_app::testing::VecLogger::default())),
        };
        assert!(start(c, &opts)
            .err()
            .unwrap()
            .contains("cannot open the audit log"));
    }
}
