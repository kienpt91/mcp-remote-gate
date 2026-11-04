//! Shared helpers of the integration tests: building configurations, starting the gateway in
//! this process or as a real program, and talking to it over HTTP.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use gate_app::testing::VecLogger;
use gate_domain::auth::{token_from_entropy, TokenHash};
use gate_domain::json::{self, Value};
use gate_infra::config_file;
use gate_infra::httpclient::{request, ClientResponse};
use gate_infra::runtime::{start, RunOptions, RunningGate};
use gate_infra::testutil::TempDir;

pub const EXE: &str = env!("CARGO_BIN_EXE_mcp-remote-gate");

pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A configuration under construction; each part can be replaced.
pub struct Setup {
    pub dir: TempDir,
    pub port: u16,
    pub token: String,
    pub hash: String,
    pub server: String,
    pub child_args: String,
    pub child_extra: String,
    pub tools: String,
    pub limits: String,
    pub audit_extra: String,
    pub extra: String,
    pub listen: Option<String>,
    pub request_timeout_ms: u32,
    /// Replaces the `command = [...]` list of the child (TOML text) when set.
    pub command: Option<String>,
}

impl Setup {
    pub fn new(label: &str) -> Setup {
        let token = token_from_entropy(&gate_infra::system::random_bytes().unwrap());
        Setup {
            dir: TempDir::new(label),
            port: free_port(),
            hash: TokenHash::of_token(&token).to_config_string(),
            token,
            server: String::new(),
            child_args: String::new(),
            child_extra: "restart = \"never\"\n".into(),
            tools: "allow = [\"*\"]\nread_only = true\n".into(),
            limits: "requests_per_minute = 6000\nburst = 1000\n".into(),
            audit_extra: String::new(),
            extra: String::new(),
            listen: None,
            request_timeout_ms: 5000,
            command: None,
        }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn text(&self) -> String {
        let listen = self
            .listen
            .clone()
            .unwrap_or_else(|| format!("127.0.0.1:{}", self.port));
        format!(
            "[server]\nlisten = \"{listen}\"\nkill_switch_file = \"{kill}\"\nrequest_timeout_ms = {timeout}\n{server}\n\
             [child]\ncommand = {command}\n{child_extra}\n[child.env]\nFAKE_MCP_SENT_LOG = \"{sent}\"\n\n\
             [tools]\n{tools}\n[limits]\n{limits}\n[audit]\npath = \"{audit}\"\n{audit_extra}\n{extra}\n\
             [[token]]\nid = \"tester\"\nhash = \"{hash}\"\n",
            kill = self.path("KILL").display(),
            command = self.command.clone().unwrap_or_else(|| format!("[\"{EXE}\", \"fake-mcp\"{}]", self.child_args)),
            timeout = self.request_timeout_ms,
            server = self.server,
            child_extra = self.child_extra,
            sent = self.path("sent.log").display(),
            tools = self.tools,
            limits = self.limits,
            audit = self.path("audit.jsonl").display(),
            audit_extra = self.audit_extra,
            extra = self.extra,
            hash = self.hash,
        )
    }

    /// Writes `gate.toml` (mode 0600) and returns its path.
    pub fn write_config(&self) -> PathBuf {
        let path = self.path("gate.toml");
        std::fs::write(&path, self.text()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    pub fn addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.port).parse().unwrap()
    }

    pub fn sent_log(&self) -> String {
        std::fs::read_to_string(self.path("sent.log")).unwrap_or_default()
    }

    pub fn audit_lines(&self) -> Vec<Value> {
        std::fs::read_to_string(self.path("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| json::parse(l).unwrap())
            .collect()
    }
}

pub struct Gate {
    pub running: RunningGate,
    pub addr: SocketAddr,
    pub log: Arc<VecLogger>,
}

pub fn try_start(setup: &Setup) -> (Result<RunningGate, String>, Arc<VecLogger>) {
    let path = setup.write_config();
    let config = config_file::load(&path)
        .unwrap_or_else(|e| panic!("invalid test configuration: {e:?}\n{}", setup.text()));
    let log = Arc::new(VecLogger::default());
    let opts = RunOptions {
        allow_non_loopback: false,
        use_signals: false,
        gate_version: "test".into(),
        logger: Some(log.clone()),
    };
    (start(config, &opts), log)
}

pub fn start_gate(setup: &Setup) -> Gate {
    let (running, log) = try_start(setup);
    let running = running.unwrap_or_else(|e| panic!("the gateway did not start: {e}"));
    let addr = running.local_addr();
    Gate { running, addr, log }
}

pub fn post(addr: SocketAddr, token: Option<&str>, body: &str) -> ClientResponse {
    let auth = token.map(|t| format!("Bearer {t}"));
    let mut headers = vec![
        ("Content-Type", "application/json"),
        ("Accept", "application/json"),
    ];
    if let Some(a) = &auth {
        headers.push(("Authorization", a));
    }
    request(
        addr,
        "POST",
        "/mcp",
        &headers,
        body.as_bytes(),
        Duration::from_secs(20),
    )
    .unwrap()
}

pub fn rpc(id: u32, method: &str, params: &str) -> String {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{method}\",\"params\":{params}}}")
}

pub fn call_tool(addr: SocketAddr, token: &str, name: &str, args: &str) -> ClientResponse {
    post(
        addr,
        Some(token),
        &rpc(
            1,
            "tools/call",
            &format!("{{\"name\":\"{name}\",\"arguments\":{args}}}"),
        ),
    )
}

pub fn body(r: &ClientResponse) -> Value {
    json::parse(&r.text()).unwrap_or_else(|e| panic!("not JSON ({e}): {}", r.text()))
}

pub fn error_code(r: &ClientResponse) -> Option<i64> {
    match body(r).get("error")?.get("code")? {
        Value::Number(n) => n.parse().ok(),
        _ => None,
    }
}

pub fn tool_names(r: &ClientResponse) -> Vec<String> {
    body(r)
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .filter_map(|t| t.get("name").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !condition() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub fn process_exists(pid: u32) -> bool {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
    // a zombie is gone as far as these tests are concerned
    stat.is_ok_and(|s| !s.contains(") Z"))
}
