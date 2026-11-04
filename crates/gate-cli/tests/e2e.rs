//! End to end through the real binary: `token new`, `check`, `tools`, `run` with signals,
//! `selftest`, and the refusals that protect the operator.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;

fn gate(args: &[&str]) -> Output {
    Command::new(EXE).args(args).output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A running `mcp-remote-gate run`, with its standard error collected.
struct Running {
    child: Child,
    stderr: Arc<Mutex<Vec<String>>>,
}

impl Running {
    fn start(config: &std::path::Path, extra: &[&str]) -> Running {
        let mut child = Command::new(EXE)
            .args(["run", "--config", config.to_str().unwrap()])
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&stderr);
        let pipe = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                sink.lock().unwrap().push(line);
            }
        });
        Running { child, stderr }
    }

    fn started(config: &std::path::Path) -> Running {
        let r = Running::start(config, &[]);
        r.wait_for_log("ready on");
        r
    }

    fn log(&self) -> String {
        self.stderr.lock().unwrap().join("\n")
    }

    fn wait_for_log(&self, needle: &str) {
        wait_for(&format!("{needle:?} in the log"), || {
            self.stderr
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.contains(needle))
        });
    }

    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .args([&format!("-{name}"), &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn wait_exit(&mut self) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code().unwrap_or(-1);
            }
            assert!(
                Instant::now() < deadline,
                "the gateway did not exit; log:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn version_help_and_usage_errors() {
    let out = gate(&["version"]);
    assert!(out.status.success() && text(&out.stdout).starts_with("mcp-remote-gate "));
    assert!(text(&gate(&["help"]).stdout).contains("token new"));
    let bad = gate(&["nonsense"]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(text(&bad.stderr).contains("unknown command"));
    assert_eq!(gate(&[]).status.code(), Some(2));
}

#[test]
fn token_hash_matches_sha256sum() {
    let mut child = Command::new(EXE)
        .args(["token", "hash"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"mrg_example-token\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let ours = text(&out.stdout).trim().to_string();
    let reference = Command::new("sh")
        .args(["-c", "printf %s mrg_example-token | sha256sum"])
        .output()
        .unwrap();
    let digest = text(&reference.stdout);
    let digest = digest.split_whitespace().next().unwrap();
    assert_eq!(ours, format!("sha256:{digest}"));
}

#[test]
fn a_token_from_token_new_works_against_a_running_gateway() {
    let out = gate(&["token", "new", "--id", "tester"]);
    assert!(out.status.success());
    let stdout = text(&out.stdout);
    let token = stdout
        .lines()
        .next()
        .unwrap()
        .strip_prefix("token: ")
        .unwrap()
        .to_string();
    let hash = stdout
        .lines()
        .find_map(|l| l.strip_prefix("hash = \""))
        .unwrap()
        .trim_end_matches('"')
        .to_string();
    let mut s = Setup::new("e2e-flow");
    s.token = token.clone();
    s.hash = hash;
    let config = s.write_config();

    let check = gate(&["check", "--config", config.to_str().unwrap()]);
    assert!(check.status.success(), "{}", text(&check.stderr));
    assert!(text(&check.stdout).contains("token:       tester (tools:list, tools:call)"));

    let tools = gate(&["tools", "--config", config.to_str().unwrap()]);
    assert!(tools.status.success(), "{}", text(&tools.stderr));
    let listing = text(&tools.stdout);
    assert!(listing.contains("server: fake-whatsapp 0.1.0"), "{listing}");
    assert!(
        listing.contains("list_chats") && listing.contains("exposed"),
        "{listing}"
    );
    let blocked = listing
        .lines()
        .find(|l| l.contains("send_message"))
        .unwrap();
    assert!(blocked.contains("blocked (read_only)"), "{blocked}");
    assert!(
        listing.contains("12 tools") && listing.contains("blocked"),
        "{listing}"
    );

    let mut run = Running::started(&config);
    let r = call_tool(s.addr(), &token, "list_chats", "{}");
    assert!(r.text().contains("Alice"), "{}", r.text());
    assert_eq!(
        error_code(&call_tool(
            s.addr(),
            &token,
            "send_message",
            "{\"to\":\"a\",\"text\":\"b\"}"
        )),
        Some(-32003)
    );
    assert_eq!(
        post(s.addr(), Some("mrg_wrong"), &rpc(1, "ping", "{}")).status,
        401
    );
    run.signal("TERM");
    assert_eq!(run.wait_exit(), 0);
    assert!(run.log().contains("shutting down"), "{}", run.log());
    let audit = std::fs::read_to_string(s.path("audit.jsonl")).unwrap();
    assert_eq!(audit.lines().count(), 3);
    assert!(!audit.contains(&token));
}

#[test]
fn sigterm_stops_the_child_tree_and_exits_zero() {
    let mut s = Setup::new("e2e-term");
    let pidfile = s.path("child.pid");
    s.command = Some(format!(
        "[\"sh\", \"-c\", \"echo $$ > {}; exec \\\"$0\\\" \\\"$@\\\"\", \"{EXE}\", \"fake-mcp\"]",
        pidfile.display()
    ));
    let config = s.write_config();
    let mut run = Running::started(&config);
    let pid: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(process_exists(pid));
    run.signal("TERM");
    assert_eq!(run.wait_exit(), 0);
    wait_for("the child to be gone", || !process_exists(pid));
}

#[test]
fn sigint_also_shuts_down_gracefully() {
    let s = Setup::new("e2e-int");
    let mut run = Running::started(&s.write_config());
    run.signal("INT");
    assert_eq!(run.wait_exit(), 0);
}

#[test]
fn killing_the_gateway_hard_does_not_leave_the_child_behind() {
    let mut s = Setup::new("e2e-kill9");
    let pidfile = s.path("child.pid");
    s.command = Some(format!(
        "[\"sh\", \"-c\", \"echo $$ > {}; exec \\\"$0\\\" \\\"$@\\\"\", \"{EXE}\", \"fake-mcp\"]",
        pidfile.display()
    ));
    let config = s.write_config();
    let mut run = Running::started(&config);
    let pid: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    run.child.kill().unwrap();
    let _ = run.child.wait();
    wait_for("the child to notice that its parent is gone", || {
        !process_exists(pid)
    });
}

#[test]
fn signals_switch_the_gateway_off_and_on() {
    let s = Setup::new("e2e-usr");
    let run = Running::started(&s.write_config());
    assert_eq!(
        post(s.addr(), Some(&s.token), &rpc(1, "ping", "{}")).status,
        200
    );
    run.signal("USR1");
    wait_for("503 after SIGUSR1", || {
        post(s.addr(), Some(&s.token), &rpc(2, "ping", "{}")).status == 503
    });
    run.signal("USR2");
    wait_for("200 after SIGUSR2", || {
        post(s.addr(), Some(&s.token), &rpc(3, "ping", "{}")).status == 200
    });
}

#[test]
fn a_non_loopback_address_needs_the_flag() {
    let mut s = Setup::new("e2e-bind");
    s.listen = Some(format!("0.0.0.0:{}", s.port));
    s.server = format!(
        "allowed_hosts = [\"gate.example.com\", \"127.0.0.1:{}\"]\n",
        s.port
    );
    let config = s.write_config();
    let refused = gate(&["run", "--config", config.to_str().unwrap()]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(
        text(&refused.stderr).contains("--i-know-this-is-not-tls"),
        "{}",
        text(&refused.stderr)
    );
    assert!(
        std::net::TcpStream::connect_timeout(&s.addr(), Duration::from_millis(300)).is_err(),
        "nothing is listening"
    );

    let mut run = Running::start(&config, &["--i-know-this-is-not-tls"]);
    run.wait_for_log("ready on");
    assert!(
        run.log().contains("not a loopback address"),
        "the warning is shown:\n{}",
        run.log()
    );
    assert_eq!(
        post(s.addr(), Some(&s.token), &rpc(1, "ping", "{}")).status,
        200
    );
    run.signal("TERM");
    assert_eq!(run.wait_exit(), 0);
}

#[test]
fn bad_configurations_are_refused_with_every_problem() {
    let s = Setup::new("e2e-bad");
    let path = s.path("gate.toml");
    std::fs::write(
        &path,
        "[server]\nlisten = \"localhost:80\"\nlisten_on = 1\n[tools]\nallow = [\"\"]\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = gate(&["run", "--config", path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    let err = text(&out.stderr);
    for expected in [
        "server.listen",
        "server.listen_on: unknown key",
        "tools.allow[0]",
        "child.command",
        "token",
    ] {
        assert!(err.contains(expected), "{expected} not in\n{err}");
    }
}

#[test]
fn a_config_that_others_can_write_is_refused() {
    let s = Setup::new("e2e-perm");
    let path = s.write_config();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    let out = gate(&["check", "--config", path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("can be written by other users"));
}

#[test]
fn a_child_that_cannot_start_is_a_runtime_failure() {
    let mut s = Setup::new("e2e-nochild");
    s.command = Some("[\"/nonexistent/program\"]".into());
    let out = gate(&["run", "--config", s.write_config().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("upstream server did not start"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_busy_port_is_a_runtime_failure_and_the_child_is_cleaned_up() {
    let s = Setup::new("e2e-port");
    let _hold = std::net::TcpListener::bind(s.addr()).unwrap();
    let out = gate(&["run", "--config", s.write_config().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("cannot listen"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn selftest_passes() {
    let out = gate(&["selftest"]);
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "{stdout}\n{}", text(&out.stderr));
    assert!(stdout.contains("15 checks, 0 failed"), "{stdout}");
    assert_eq!(stdout.matches("  ok    ").count(), 15);
    assert!(!stdout.contains("FAIL"));
}

#[test]
fn init_prints_a_configuration_that_check_accepts_once_the_hash_is_real() {
    let out = gate(&["init"]);
    assert!(out.status.success());
    let s = Setup::new("e2e-init");
    let path = s.path("gate.toml");
    std::fs::write(&path, text(&out.stdout)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let check = gate(&["check", "--config", path.to_str().unwrap()]);
    assert!(check.status.success(), "{}", text(&check.stderr));
}
