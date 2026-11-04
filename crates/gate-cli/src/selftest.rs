//! `selftest`: starts the gateway in front of the bundled fake server on a free loopback port
//! and checks, through real HTTP, the behavior the security model promises.

use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gate_app::ports::{Level, Logger};
use gate_domain::auth::{token_from_entropy, TokenHash};
use gate_domain::json::{self, quote, Value};
use gate_infra::config_file;
use gate_infra::httpclient::{request, ClientResponse};
use gate_infra::runtime::{start, RunOptions, RunningGate};
use gate_infra::system::random_bytes;

use crate::{usage_error, Io, FAILED, OK};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> std::io::Result<Scratch> {
        let entropy: [u8; 6] = random_bytes()?;
        let name: String = entropy.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("mcp-remote-gate-selftest-{name}"));
        std::fs::create_dir(&path)?;
        Ok(Scratch(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct Quiet(Mutex<Vec<String>>);

impl Logger for Quiet {
    fn log(&self, _level: Level, message: &str) {
        if let Ok(mut lines) = self.0.lock() {
            lines.push(message.to_string());
        }
    }
}

struct Report {
    results: Vec<(String, Result<(), String>)>,
}

impl Report {
    fn check(&mut self, name: &str, outcome: Result<(), String>) {
        self.results.push((name.to_string(), outcome));
    }
}

fn free_port() -> std::io::Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn config_text(exe: &Path, dir: &Path, port: u16, hash: &str, read_only: bool) -> String {
    let path = |name: &str| quote(&dir.join(name).to_string_lossy());
    format!(
        "[server]\nlisten = \"127.0.0.1:{port}\"\nmax_request_bytes = 4096\nkill_switch_file = {kill}\n\n\
         [child]\ncommand = [{exe}, \"fake-mcp\"]\nrestart = \"never\"\n[child.env]\nFAKE_MCP_SENT_LOG = {sent}\n\n\
         [tools]\nallow = [\"*\"]\nread_only = {read_only}\n\n\
         [limits]\nrequests_per_minute = 600\nburst = 100\n\n\
         [audit]\npath = {audit}\n\n\
         [[token]]\nid = \"selftest\"\nhash = {hash}\n",
        kill = path("KILL"),
        exe = quote(&exe.to_string_lossy()),
        sent = path("sent.log"),
        audit = path("audit.jsonl"),
        hash = quote(hash),
    )
}

fn post(
    addr: SocketAddr,
    token: Option<&str>,
    extra: &[(&str, &str)],
    body: &str,
) -> Result<ClientResponse, String> {
    let auth = token.map(|t| format!("Bearer {t}"));
    let mut headers: Vec<(&str, &str)> = vec![
        ("Content-Type", "application/json"),
        ("Accept", "application/json"),
    ];
    if let Some(a) = &auth {
        headers.push(("Authorization", a));
    }
    headers.extend_from_slice(extra);
    request(
        addr,
        "POST",
        "/mcp",
        &headers,
        body.as_bytes(),
        Duration::from_secs(10),
    )
    .map_err(|e| e.to_string())
}

fn rpc(id: u32, method: &str, params: &str) -> String {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{method}\",\"params\":{params}}}")
}

fn expect_status(r: &ClientResponse, status: u16) -> Result<(), String> {
    if r.status == status {
        Ok(())
    } else {
        Err(format!(
            "expected HTTP {status}, got {} ({})",
            r.status,
            r.text().chars().take(120).collect::<String>()
        ))
    }
}

fn error_code(r: &ClientResponse) -> Option<i64> {
    let v = json::parse(&r.text()).ok()?;
    match v.get("error")?.get("code")? {
        Value::Number(n) => n.parse().ok(),
        _ => None,
    }
}

fn start_gate(
    exe: &Path,
    dir: &Path,
    port: u16,
    hash: &str,
    read_only: bool,
    log: &Arc<Quiet>,
) -> Result<RunningGate, String> {
    let config_path = dir.join("gate.toml");
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&config_path)
            .map_err(|e| e.to_string())?;
        f.write_all(config_text(exe, dir, port, hash, read_only).as_bytes())
            .map_err(|e| e.to_string())?;
    }
    let config = config_file::load(&config_path).map_err(|p| p.join("; "))?;
    let opts = RunOptions {
        allow_non_loopback: false,
        use_signals: false,
        gate_version: crate::VERSION.to_string(),
        logger: Some(log.clone()),
    };
    start(config, &opts)
}

fn read_only_phase(report: &mut Report, addr: SocketAddr, token: &str, dir: &Path) {
    let wrong = token_from_entropy(&[0xaa; 32]);
    report.check(
        "a request without a token is refused with 401",
        post(addr, None, &[], &rpc(1, "ping", "{}")).and_then(|r| expect_status(&r, 401)),
    );
    report.check(
        "a wrong token is refused with 401",
        post(addr, Some(&wrong), &[], &rpc(1, "ping", "{}")).and_then(|r| expect_status(&r, 401)),
    );
    report.check(
        "a foreign Host header is refused with 403",
        post(
            addr,
            Some(token),
            &[("Host", "evil.example:80")],
            &rpc(1, "ping", "{}"),
        )
        .and_then(|r| expect_status(&r, 403)),
    );
    report.check(
        "a browser Origin is refused with 403",
        post(
            addr,
            Some(token),
            &[("Origin", "https://evil.example")],
            &rpc(1, "ping", "{}"),
        )
        .and_then(|r| expect_status(&r, 403)),
    );
    report.check(
        "initialize is answered",
        post(addr, Some(token), &[], &rpc(1, "initialize", "{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"selftest\",\"version\":\"1\"}}"))
            .and_then(|r| expect_status(&r, 200).and_then(|()| if r.text().contains("via mcp-remote-gate") { Ok(()) } else { Err("no serverInfo".into()) })),
    );
    report.check(
        "tools/list shows the read tools and hides the write tools",
        post(addr, Some(token), &[], &rpc(2, "tools/list", "{}")).and_then(|r| {
            expect_status(&r, 200)?;
            let text = r.text();
            if !text.contains("list_chats") || !text.contains("get_messages") {
                return Err("a read tool is missing".into());
            }
            for hidden in ["send_message", "delete_chat", "crash", "huge_line"] {
                if text.contains(hidden) {
                    return Err(format!("{hidden} is listed"));
                }
            }
            Ok(())
        }),
    );
    report.check(
        "a read tool call passes",
        post(
            addr,
            Some(token),
            &[],
            &rpc(
                3,
                "tools/call",
                "{\"name\":\"list_chats\",\"arguments\":{}}",
            ),
        )
        .and_then(|r| {
            expect_status(&r, 200).and_then(|()| {
                if r.text().contains("Alice") {
                    Ok(())
                } else {
                    Err("no result".into())
                }
            })
        }),
    );
    report.check(
        "send_message is denied",
        post(addr, Some(token), &[], &rpc(4, "tools/call", "{\"name\":\"send_message\",\"arguments\":{\"to\":\"alice\",\"text\":\"selftest-secret-text\"}}"))
            .and_then(|r| if error_code(&r) == Some(-32003) { Ok(()) } else { Err(format!("expected error -32003, got {}", r.text())) }),
    );
    report.check(
        "the denied call never reached the server",
        if dir.join("sent.log").exists() {
            Err("the fake server recorded a write".into())
        } else {
            Ok(())
        },
    );
    let big = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"ping\",\"params\":{{\"x\":\"{}\"}}}}",
        "a".repeat(8000)
    );
    report.check(
        "an oversized body is refused with 413",
        post(addr, Some(token), &[], &big).and_then(|r| expect_status(&r, 413)),
    );
    report.check("the kill switch file answers 503", {
        let kill = dir.join("KILL");
        let created = std::fs::write(&kill, b"").map_err(|e| e.to_string());
        let answer = created
            .and_then(|()| post(addr, Some(token), &[], &rpc(6, "ping", "{}")))
            .and_then(|r| expect_status(&r, 503));
        let _ = std::fs::remove_file(&kill);
        answer
    });
    report.check(
        "the gateway answers again when the kill switch file is gone",
        post(addr, Some(token), &[], &rpc(7, "ping", "{}")).and_then(|r| expect_status(&r, 200)),
    );
    report.check(
        "the audit log records the denial and holds no secret",
        audit_check(dir, token, "selftest-secret-text"),
    );
}

fn audit_check(dir: &Path, token: &str, secret_text: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(dir.join("audit.jsonl"))
        .map_err(|e| format!("cannot read the audit log: {e}"))?;
    if text.contains(token) || text.contains(secret_text) {
        return Err("the audit log holds the token or an argument value".into());
    }
    let denied = text.lines().filter_map(|l| json::parse(l).ok()).any(|v| {
        v.get("tool").and_then(Value::as_str) == Some("send_message")
            && v.get("outcome").and_then(Value::as_str) == Some("denied")
            && v.get("reason").and_then(Value::as_str) == Some("read_only")
            && v.get("token").and_then(Value::as_str) == Some("selftest")
    });
    if denied {
        Ok(())
    } else {
        Err("no record of the denied send_message".into())
    }
}

fn sending_phase(report: &mut Report, addr: SocketAddr, token: &str, dir: &Path) {
    report.check(
        "with read_only = false the tool list includes send_message",
        post(addr, Some(token), &[], &rpc(1, "tools/list", "{}")).and_then(|r| {
            if r.text().contains("send_message") {
                Ok(())
            } else {
                Err("not listed".into())
            }
        }),
    );
    report.check(
        "with read_only = false send_message reaches the server",
        post(
            addr,
            Some(token),
            &[],
            &rpc(
                2,
                "tools/call",
                "{\"name\":\"send_message\",\"arguments\":{\"to\":\"alice\",\"text\":\"hi\"}}",
            ),
        )
        .and_then(|r| {
            expect_status(&r, 200)?;
            let log = std::fs::read_to_string(dir.join("sent.log"))
                .map_err(|_| "the server recorded no write".to_string())?;
            if log.contains("send_message to=alice") {
                Ok(())
            } else {
                Err(format!("unexpected record: {log}"))
            }
        }),
    );
}

fn execute(exe: &Path, report: &mut Report) -> Result<(), String> {
    let scratch = Scratch::new().map_err(|e| format!("cannot create a scratch directory: {e}"))?;
    let dir = scratch.0.as_path();
    let entropy: [u8; 32] = random_bytes().map_err(|e| format!("cannot read random bytes: {e}"))?;
    let token = token_from_entropy(&entropy);
    let hash = TokenHash::of_token(&token).to_config_string();
    let log = Arc::new(Quiet::default());
    let port = free_port().map_err(|e| format!("cannot find a free port: {e}"))?;
    let gate = start_gate(exe, dir, port, &hash, true, &log)?;
    read_only_phase(report, gate.local_addr(), &token, dir);
    gate.stop(Duration::from_secs(3));
    let port = free_port().map_err(|e| format!("cannot find a free port: {e}"))?;
    let gate = start_gate(exe, dir, port, &hash, false, &log)?;
    sending_phase(report, gate.local_addr(), &token, dir);
    gate.stop(Duration::from_secs(3));
    Ok(())
}

pub fn run(args: &[String], io: &mut Io<'_>) -> i32 {
    if !args.is_empty() {
        return usage_error(io, "selftest takes no arguments");
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            let _ = writeln!(io.err, "error: cannot find this program: {e}");
            return FAILED;
        }
    };
    let mut report = Report {
        results: Vec::new(),
    };
    if let Err(e) = execute(&exe, &mut report) {
        let _ = writeln!(io.err, "error: the selftest could not run: {e}");
        return FAILED;
    }
    let mut failed = 0;
    for (name, outcome) in &report.results {
        match outcome {
            Ok(()) => {
                let _ = writeln!(io.out, "  ok    {name}");
            }
            Err(why) => {
                failed += 1;
                let _ = writeln!(io.out, "  FAIL  {name}: {why}");
            }
        }
    }
    let _ = writeln!(io.out, "{} checks, {failed} failed", report.results.len());
    if failed == 0 {
        OK
    } else {
        FAILED
    }
}
