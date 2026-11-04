//! The gateway in this process, in front of a real child process (the bundled fake server) and
//! reached over real TCP sockets: the adapters working together, with the failure modes of the
//! child (slow, crashing, noisy, oversized) exercised for real.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::time::{Duration, Instant};

use common::*;
use gate_domain::json::Value;

#[test]
fn read_tools_pass_and_write_tools_are_hidden_and_denied() {
    let s = Setup::new("ad-read");
    let g = start_gate(&s);
    let list = post(g.addr, Some(&s.token), &rpc(1, "tools/list", "{}"));
    let names = tool_names(&list);
    assert!(
        names.contains(&"list_chats".to_string()) && names.contains(&"get_messages".to_string()),
        "{names:?}"
    );
    for hidden in [
        "send_message",
        "delete_chat",
        "crash",
        "slow_tool",
        "echo",
        "inject",
    ] {
        assert!(
            !names.contains(&hidden.to_string()),
            "{hidden} must not be listed"
        );
    }
    let r = call_tool(g.addr, &s.token, "list_chats", "{}");
    assert!(r.text().contains("Alice"), "{}", r.text());
    let r = call_tool(
        g.addr,
        &s.token,
        "send_message",
        "{\"to\":\"alice\",\"text\":\"hi\"}",
    );
    assert_eq!(error_code(&r), Some(-32003));
    assert_eq!(s.sent_log(), "", "the denied call never reached the server");
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn one_line_in_the_config_enables_sending() {
    let mut s = Setup::new("ad-switch");
    s.tools = "allow = [\"*\"]\nread_only = false\n".into();
    let g = start_gate(&s);
    assert!(
        tool_names(&post(g.addr, Some(&s.token), &rpc(1, "tools/list", "{}")))
            .contains(&"send_message".to_string())
    );
    let r = call_tool(
        g.addr,
        &s.token,
        "send_message",
        "{\"to\":\"alice\",\"text\":\"hi\"}",
    );
    assert!(r.text().contains("message sent to alice"), "{}", r.text());
    assert!(s.sent_log().contains("send_message to=alice text=hi"));
    assert!(
        g.log.contains("WRITE TOOL CALLED"),
        "the stderr of the child reaches the log"
    );
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn a_deny_list_blocks_sending_while_everything_else_is_open() {
    let mut s = Setup::new("ad-deny");
    s.tools =
        "allow = [\"*\"]\ndeny = [\"send_*\", \"delete_*\", \"crash\"]\nread_only = false\n".into();
    let g = start_gate(&s);
    let names = tool_names(&post(g.addr, Some(&s.token), &rpc(1, "tools/list", "{}")));
    assert!(
        names.contains(&"echo".to_string())
            && !names.contains(&"send_message".to_string())
            && !names.contains(&"delete_chat".to_string())
    );
    assert_eq!(
        error_code(&call_tool(
            g.addr,
            &s.token,
            "delete_chat",
            "{\"chat\":\"c1\"}"
        )),
        Some(-32003)
    );
    assert_eq!(s.sent_log(), "");
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn argument_rules_stop_a_call_before_it_reaches_the_server() {
    let mut s = Setup::new("ad-args");
    s.tools = "allow = [\"*\"]\nread_only = false\n[[tools.rule]]\ntool = \"send_*\"\nmax_string_len = 20\nforbid_values = [\"*://*\", \"+1555*\"]\n".into();
    let g = start_gate(&s);
    for args in [
        "{\"to\":\"alice\",\"text\":\"see http://phish.example\"}",
        "{\"to\":\"+15551234\",\"text\":\"hi\"}",
        "{\"to\":\"alice\",\"text\":\"a very very long message indeed\"}",
    ] {
        assert_eq!(
            error_code(&call_tool(g.addr, &s.token, "send_message", args)),
            Some(-32003),
            "{args}"
        );
    }
    assert_eq!(s.sent_log(), "");
    assert!(call_tool(
        g.addr,
        &s.token,
        "send_message",
        "{\"to\":\"alice\",\"text\":\"hi\"}"
    )
    .text()
    .contains("message sent"));
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn concurrent_calls_each_get_their_own_answer() {
    let mut s = Setup::new("ad-conc");
    s.tools = "allow = [\"*\"]\nread_only = false\n".into();
    s.limits.push_str("max_inflight = 64\n");
    let g = start_gate(&s);
    let (addr, token) = (g.addr, s.token.clone());
    let handles: Vec<_> = (0..32)
        .map(|i| {
            let token = token.clone();
            std::thread::spawn(move || {
                let r = call_tool(addr, &token, "echo", &format!("{{\"n\":{i}}}"));
                assert!(
                    r.text().contains(&format!("{{\\\"n\\\":{i}}}")),
                    "{}",
                    r.text()
                );
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn a_slow_tool_times_out_and_the_gateway_keeps_serving() {
    let mut s = Setup::new("ad-slow");
    s.tools = "allow = [\"*\"]\nread_only = false\n".into();
    s.request_timeout_ms = 400;
    let g = start_gate(&s);
    let started = Instant::now();
    let r = call_tool(g.addr, &s.token, "slow_tool", "{\"ms\":1500}");
    assert_eq!(error_code(&r), Some(-32001), "{}", r.text());
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert!(call_tool(g.addr, &s.token, "echo", "{}")
        .text()
        .contains("result"));
    wait_for("the late answer to be dropped", || {
        g.running.upstream_stats().late_responses == 1
    });
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn a_crashing_child_gives_503_and_is_restarted() {
    let mut s = Setup::new("ad-crash");
    s.tools = "allow = [\"*\"]\nread_only = false\n".into();
    s.child_extra = "restart = \"on-failure\"\nmax_restarts = 3\nrestart_backoff_ms = 50\n".into();
    let g = start_gate(&s);
    let r = call_tool(g.addr, &s.token, "crash", "{}");
    assert_eq!(r.status, 503, "{}", r.text());
    wait_for("the restart", || {
        call_tool(g.addr, &s.token, "echo", "{}").status == 200
    });
    assert!(g.running.upstream_stats().restarts >= 1);
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn without_restarts_a_dead_child_means_503_for_everyone() {
    let mut s = Setup::new("ad-norestart");
    s.tools = "allow = [\"*\"]\nread_only = false\n".into();
    let g = start_gate(&s);
    assert_eq!(call_tool(g.addr, &s.token, "crash", "{}").status, 503);
    wait_for("the final state", || {
        g.running.upstream_status().starts_with("Gone")
    });
    let r = call_tool(g.addr, &s.token, "echo", "{}");
    assert_eq!(r.status, 503);
    assert!(
        !r.text().contains("exit status"),
        "internals are not shown to clients: {}",
        r.text()
    );
    assert_eq!(
        post(g.addr, Some(&s.token), &rpc(1, "ping", "{}")).status,
        200,
        "the gateway itself still answers"
    );
    assert_eq!(
        post(g.addr, Some(&s.token), &rpc(1, "initialize", "{}")).status,
        503
    );
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn big_results_are_cut_and_labelled() {
    let mut s = Setup::new("ad-big");
    s.tools = "allow = [\"*\"]\nread_only = false\n".into();
    s.limits
        .push_str("result_max_bytes = 2048\ntool_result_prefix = \"[untrusted tool output] \"\n");
    let g = start_gate(&s);
    let r = call_tool(g.addr, &s.token, "big_output", "{\"bytes\":100000}");
    assert!(r.body.len() <= 2048 + 64, "{}", r.body.len());
    assert!(r.text().contains("[untrusted tool output] ") && r.text().contains("truncated"));
    let r = call_tool(g.addr, &s.token, "inject", "{}");
    assert!(
        r.text().contains("[untrusted tool output] Meeting notes."),
        "{}",
        r.text()
    );
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn a_reply_line_over_the_child_limit_fails_its_call_at_once() {
    let mut s = Setup::new("ad-line");
    s.tools = "allow = [\"*\"]\nread_only = false\n".into();
    s.child_extra = "restart = \"never\"\nmax_line_bytes = 65536\n".into();
    let g = start_gate(&s);
    let started = Instant::now();
    let r = call_tool(g.addr, &s.token, "big_output", "{\"bytes\":300000}");
    assert_eq!(error_code(&r), Some(-32004), "{}", r.text());
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(g.running.upstream_stats().oversized_lines, 1);
    assert!(call_tool(g.addr, &s.token, "echo", "{}")
        .text()
        .contains("result"));
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn a_huge_line_that_is_no_answer_is_dropped_and_the_session_survives() {
    let mut s = Setup::new("ad-huge");
    s.tools = "allow = [\"*\"]\nread_only = false\n".into();
    s.child_extra = "restart = \"never\"\nmax_line_bytes = 65536\n".into();
    s.request_timeout_ms = 600;
    let g = start_gate(&s);
    // huge_line prints an unrelated line of 400 kB and never answers: the call times out
    let r = call_tool(g.addr, &s.token, "huge_line", "{\"bytes\":400000}");
    assert_eq!(error_code(&r), Some(-32001), "{}", r.text());
    wait_for("the oversized line to be counted", || {
        g.running.upstream_stats().oversized_lines == 1
    });
    assert!(call_tool(g.addr, &s.token, "echo", "{}")
        .text()
        .contains("result"));
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn a_noisy_child_is_tolerated_and_its_noise_is_neutralised() {
    let mut s = Setup::new("ad-noisy");
    s.tools = "allow = [\"*\"]\nread_only = false\n".into();
    let g = start_gate(&s);
    let r = call_tool(g.addr, &s.token, "noisy", "{}");
    assert!(r.text().contains("done"), "{}", r.text());
    let stats = g.running.upstream_stats();
    assert!(
        stats.invalid_lines >= 1 && stats.ignored_notifications >= 1 && stats.child_requests >= 1,
        "{stats:?}"
    );
    wait_for("stderr in the log", || g.log.contains("noise"));
    assert!(
        g.log.lines().iter().all(|(_, m)| !m.contains('\u{1b}')),
        "control characters must not reach the log"
    );
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn the_server_instructions_and_unlisted_methods_do_not_pass() {
    let s = Setup::new("ad-init");
    let g = start_gate(&s);
    let r = post(g.addr, Some(&s.token), &rpc(1, "initialize", "{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}"));
    assert!(
        r.text().contains("fake-whatsapp") && !r.text().contains("instructions"),
        "{}",
        r.text()
    );
    for method in ["resources/list", "prompts/list", "logging/setLevel"] {
        assert_eq!(
            error_code(&post(g.addr, Some(&s.token), &rpc(2, method, "{}"))),
            Some(-32601),
            "{method}"
        );
    }
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn rate_limits_apply_per_token() {
    let mut s = Setup::new("ad-rate");
    s.limits = "requests_per_minute = 60\nburst = 5\n".into();
    let g = start_gate(&s);
    let statuses: Vec<u16> = (0..8)
        .map(|i| post(g.addr, Some(&s.token), &rpc(i, "ping", "{}")).status)
        .collect();
    assert_eq!(
        statuses.iter().filter(|s| **s == 200).count(),
        5,
        "{statuses:?}"
    );
    let limited = post(g.addr, Some(&s.token), &rpc(9, "ping", "{}"));
    assert_eq!(limited.status, 429);
    assert!(limited.header("retry-after").is_some());
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn the_kill_switch_file_takes_effect_at_once() {
    let s = Setup::new("ad-kill");
    let g = start_gate(&s);
    assert_eq!(
        post(g.addr, Some(&s.token), &rpc(1, "ping", "{}")).status,
        200
    );
    std::fs::write(s.path("KILL"), "").unwrap();
    let r = post(g.addr, Some(&s.token), &rpc(2, "ping", "{}"));
    assert_eq!((r.status, r.header("retry-after")), (503, Some("30")));
    assert_eq!(post(g.addr, None, &rpc(2, "ping", "{}")).status, 503);
    std::fs::remove_file(s.path("KILL")).unwrap();
    assert_eq!(
        post(g.addr, Some(&s.token), &rpc(3, "ping", "{}")).status,
        200
    );
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn hosts_from_the_config_are_honoured() {
    let mut s = Setup::new("ad-host");
    s.server = format!(
        "allowed_hosts = [\"gate.example.com\", \"127.0.0.1:{}\"]\n",
        s.port
    );
    let g = start_gate(&s);
    let ok = gate_infra::httpclient::request(
        g.addr,
        "POST",
        "/mcp",
        &[
            ("Host", "gate.example.com"),
            ("Content-Type", "application/json"),
            ("Authorization", &format!("Bearer {}", s.token)),
        ],
        rpc(1, "ping", "{}").as_bytes(),
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(ok.status, 200);
    let bad = gate_infra::httpclient::request(
        g.addr,
        "POST",
        "/mcp",
        &[
            ("Host", "other.example.com"),
            ("Content-Type", "application/json"),
            ("Authorization", &format!("Bearer {}", s.token)),
        ],
        rpc(1, "ping", "{}").as_bytes(),
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(bad.status, 403);
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn get_and_delete_are_not_allowed() {
    let s = Setup::new("ad-methods");
    let g = start_gate(&s);
    for method in ["GET", "DELETE"] {
        let r = gate_infra::httpclient::request(
            g.addr,
            method,
            "/mcp",
            &[("Authorization", &format!("Bearer {}", s.token))],
            b"",
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(
            (r.status, r.header("allow")),
            (405, Some("POST")),
            "{method}"
        );
    }
    assert_eq!(
        gate_infra::httpclient::request(g.addr, "GET", "/mcp", &[], b"", Duration::from_secs(5))
            .unwrap()
            .status,
        401
    );
    g.running.stop(Duration::from_secs(3));
}

#[test]
fn the_audit_log_tells_the_story_without_secrets() {
    let mut s = Setup::new("ad-audit");
    s.tools = "allow = [\"*\"]\nread_only = true\n".into();
    let g = start_gate(&s);
    let secret_text = "very-private-message-body";
    call_tool(g.addr, &s.token, "list_chats", "{}");
    call_tool(
        g.addr,
        &s.token,
        "send_message",
        &format!("{{\"to\":\"alice\",\"text\":\"{secret_text}\"}}"),
    );
    post(
        g.addr,
        Some("mrg_wrongwrongwrongwrongwrongwrongwrongwrongwrong"),
        &rpc(1, "ping", "{}"),
    );
    g.running.stop(Duration::from_secs(3));
    let raw = std::fs::read_to_string(s.path("audit.jsonl")).unwrap();
    assert!(
        !raw.contains(&s.token) && !raw.contains(secret_text) && !raw.contains("wrongwrong"),
        "{raw}"
    );
    let lines = s.audit_lines();
    assert_eq!(lines.len(), 3);
    let field = |i: usize, k: &str| lines[i].get(k).and_then(Value::as_str).map(str::to_string);
    assert_eq!(
        (field(0, "tool"), field(0, "outcome")),
        (Some("list_chats".into()), Some("allowed".into()))
    );
    assert_eq!(
        (field(1, "tool"), field(1, "outcome"), field(1, "reason")),
        (
            Some("send_message".into()),
            Some("denied".into()),
            Some("read_only".into())
        )
    );
    assert_eq!(
        (field(2, "token"), field(2, "reason")),
        (None, Some("bad_token".into()))
    );
    assert_eq!(field(0, "token"), Some("tester".into()));
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(s.path("audit.jsonl"))
            .unwrap()
            .permissions(),
    ) & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_child_that_never_answers_the_handshake_stops_the_start() {
    let mut s = Setup::new("ad-hang");
    s.child_args = ", \"--hang-on-initialize\"".into();
    s.child_extra = "restart = \"never\"\nstartup_timeout_ms = 400\n".into();
    let (result, log) = try_start(&s);
    let error = result.err().unwrap();
    assert!(error.contains("did not start"), "{error}");
    assert!(log.contains("handshake failed"));
}

#[test]
fn a_child_with_a_broken_handshake_stops_the_start() {
    let mut s = Setup::new("ad-bad");
    s.child_args = ", \"--bad-initialize\"".into();
    let (result, _) = try_start(&s);
    assert!(result.err().unwrap().contains("did not start"));
}

#[test]
fn stopping_the_gateway_stops_the_whole_child_tree() {
    let mut s = Setup::new("ad-tree");
    let pidfile = s.path("child.pid");
    // the shell records its pid, then becomes the fake server (exec keeps the pid)
    s.command = Some(format!(
        "[\"sh\", \"-c\", \"echo $$ > {}; exec \\\"$0\\\" \\\"$@\\\"\", \"{EXE}\", \"fake-mcp\"]",
        pidfile.display()
    ));
    let g = start_gate(&s);
    let pid: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(process_exists(pid));
    g.running.stop(Duration::from_secs(3));
    wait_for("the child to be gone", || !process_exists(pid));
}

#[test]
fn a_flood_of_bad_requests_does_not_stop_a_good_client() {
    let mut s = Setup::new("ad-flood");
    s.limits = "requests_per_minute = 6000\nburst = 1000\nfailed_auth_per_minute = 10\n".into();
    let g = start_gate(&s);
    let addr = g.addr;
    let handles: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(move || {
                for i in 0..25 {
                    let r = post(addr, Some("mrg_nope"), &rpc(i, "ping", "{}"));
                    assert!(r.status == 401 || r.status == 429);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        post(addr, Some(&s.token), &rpc(1, "ping", "{}")).status,
        200
    );
    g.running.stop(Duration::from_secs(3));
}
