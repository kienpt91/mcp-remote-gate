//! Tests of the upstream session against a scripted child process and a fake clock.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use gate_domain::framing::Line;
use gate_domain::json::{self, Value};
use gate_domain::jsonrpc::{self, Message};
use gate_domain::restart::{RestartMode, RestartPolicy};

use crate::ports::Read;
use crate::testing::{mcp_behavior, Behavior, ChildAction, FakeClock, ScriptedSpawner, VecLogger};
use crate::upstream::{StdioUpstream, UpstreamError, UpstreamPort, UpstreamSettings};

fn settings(mode: RestartMode, max_restarts: u32, max_inflight: usize) -> UpstreamSettings {
    UpstreamSettings {
        restart: RestartPolicy {
            mode,
            max_restarts,
            backoff_ms: 10,
            max_backoff_ms: 100,
        },
        startup_timeout_ms: 2000,
        max_inflight,
        gate_version: "0.0.0-test".into(),
    }
}

fn start(
    spawner: Arc<ScriptedSpawner>,
    settings: UpstreamSettings,
) -> (Result<StdioUpstream, String>, Arc<VecLogger>) {
    let log = Arc::new(VecLogger::default());
    let clock = Arc::new(FakeClock::new());
    (
        StdioUpstream::start(settings, spawner, clock, log.clone()),
        log,
    )
}

fn well_behaved() -> Arc<ScriptedSpawner> {
    ScriptedSpawner::always(|| mcp_behavior(&["get_chats", "send_message", "slow", "crash", "big"]))
}

fn call_params(name: &str, args: &str) -> Value {
    json::parse(&format!("{{\"name\":\"{name}\",\"arguments\":{args}}}")).unwrap()
}

fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn the_handshake_runs_before_the_session_is_ready() {
    let spawner = well_behaved();
    let (up, log) = start(spawner.clone(), settings(RestartMode::Never, 0, 8));
    let up = up.unwrap();
    let info = up.info().unwrap();
    assert_eq!(
        (info.server_name.as_str(), info.protocol_version.as_str()),
        ("scripted", "2025-06-18")
    );
    assert!(info.has_tools);
    wait_for("the initialized notification", || {
        spawner.received().len() >= 2
    });
    let received = spawner.received();
    assert!(
        received[0].contains("\"method\":\"initialize\"") && received[0].contains("0.0.0-test")
    );
    assert!(received[1].contains("notifications/initialized"));
    assert!(log.contains("upstream server ready: scripted 1.0"));
    up.shutdown();
}

#[test]
fn requests_are_renumbered_with_ids_of_the_gateway() {
    let spawner = well_behaved();
    let up = start(spawner.clone(), settings(RestartMode::Never, 0, 8))
        .0
        .unwrap();
    let r = up.request("tools/list", None, 2000).unwrap();
    assert_eq!(
        r.get("tools").and_then(Value::as_array).map(Vec::len),
        Some(5)
    );
    let r = up
        .request(
            "tools/call",
            Some(call_params("get_chats", "{\"limit\":3}")),
            2000,
        )
        .unwrap();
    assert_eq!(
        r.to_json(),
        r#"{"content":[{"type":"text","text":"get_chats:{\"limit\":3}"}]}"#
    );
    for line in spawner.received() {
        if let Ok(Message::Request { id, .. }) = jsonrpc::classify(json::parse(&line).unwrap()) {
            assert!(
                matches!(id, Value::Number(_)),
                "the child only sees numeric ids of the gateway: {line}"
            );
        }
    }
    up.shutdown();
}

#[test]
fn concurrent_calls_get_their_own_answers() {
    let spawner = well_behaved();
    let up = Arc::new(
        start(spawner, settings(RestartMode::Never, 0, 256))
            .0
            .unwrap(),
    );
    let handles: Vec<_> = (0..64)
        .map(|i| {
            let up = Arc::clone(&up);
            std::thread::spawn(move || {
                let marker = format!("{{\"n\":{i}}}");
                let r = up
                    .request("tools/call", Some(call_params("get_chats", &marker)), 5000)
                    .unwrap();
                assert!(
                    r.to_json()
                        .contains(&format!("get_chats:{{\\\"n\\\":{i}}}")),
                    "{}",
                    r.to_json()
                );
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    up.shutdown();
}

#[test]
fn a_json_rpc_error_of_the_child_is_passed_on() {
    let up = start(well_behaved(), settings(RestartMode::Never, 0, 8))
        .0
        .unwrap();
    match up.request("tools/call", Some(call_params("nope", "{}")), 2000) {
        Err(UpstreamError::Rpc(e)) => assert_eq!(
            (e.code, e.message.as_str()),
            (jsonrpc::INVALID_PARAMS, "unknown tool")
        ),
        other => panic!("{other:?}"),
    }
    match up.request("resources/list", None, 2000) {
        Err(UpstreamError::Rpc(e)) => assert_eq!(e.code, jsonrpc::METHOD_NOT_FOUND),
        other => panic!("{other:?}"),
    }
    up.shutdown();
}

#[test]
fn a_call_that_is_not_answered_times_out_and_is_cancelled() {
    let spawner = well_behaved();
    let up = start(spawner.clone(), settings(RestartMode::Never, 0, 8))
        .0
        .unwrap();
    let started = Instant::now();
    assert_eq!(
        up.request("tools/call", Some(call_params("slow", "{}")), 150),
        Err(UpstreamError::Timeout)
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    wait_for("the cancel notification", || {
        spawner
            .received()
            .iter()
            .any(|l| l.contains("notifications/cancelled"))
    });
    // the session still works
    assert!(up.request("ping", None, 2000).is_ok());
    up.shutdown();
}

#[test]
fn a_late_answer_after_a_timeout_is_counted_and_dropped() {
    let spawner = ScriptedSpawner::always(|| {
        let mut inner = mcp_behavior(&["t"]);
        let mut held: Option<String> = None;
        Box::new(move |msg: &Value| {
            let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
            let id = msg.get("id").cloned();
            if method == "tools/call" {
                held = id.map(|id| jsonrpc::response_ok(&id, Value::Object(vec![])).to_json());
                return vec![];
            }
            if method == "ping" {
                let mut out = inner(msg);
                out.extend(held.take().map(ChildAction::Say));
                return out;
            }
            inner(msg)
        })
    });
    let up = start(spawner, settings(RestartMode::Never, 0, 8))
        .0
        .unwrap();
    assert_eq!(
        up.request("tools/call", Some(call_params("t", "{}")), 100),
        Err(UpstreamError::Timeout)
    );
    up.request("ping", None, 2000).unwrap();
    wait_for("the late response", || up.stats().late_responses == 1);
    up.shutdown();
}

#[test]
fn too_many_calls_in_flight_are_refused() {
    let up = Arc::new(
        start(well_behaved(), settings(RestartMode::Never, 0, 2))
            .0
            .unwrap(),
    );
    let waiting: Vec<_> = (0..2)
        .map(|_| {
            let up = Arc::clone(&up);
            std::thread::spawn(move || {
                up.request("tools/call", Some(call_params("slow", "{}")), 1500)
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(up.request("ping", None, 1000), Err(UpstreamError::Busy));
    for w in waiting {
        assert_eq!(w.join().unwrap(), Err(UpstreamError::Timeout));
    }
    assert!(up.request("ping", None, 1000).is_ok());
    up.shutdown();
}

#[test]
fn a_crash_fails_the_calls_in_flight_and_the_child_is_restarted() {
    let spawner = well_behaved();
    let up = start(spawner.clone(), settings(RestartMode::OnFailure, 3, 8))
        .0
        .unwrap();
    match up.request("tools/call", Some(call_params("crash", "{}")), 3000) {
        Err(UpstreamError::Unavailable(why)) => assert!(why.contains("exit status 1"), "{why}"),
        other => panic!("{other:?}"),
    }
    wait_for("the restart", || {
        up.info().is_ok() && spawner.spawn_count() == 2
    });
    assert!(up.request("ping", None, 2000).is_ok());
    assert_eq!(up.stats().restarts, 1);
    up.shutdown();
}

#[test]
fn without_a_restart_policy_the_session_stays_down() {
    let spawner = well_behaved();
    let up = start(spawner.clone(), settings(RestartMode::Never, 0, 8))
        .0
        .unwrap();
    let _ = up.request("tools/call", Some(call_params("crash", "{}")), 3000);
    wait_for("the final state", || up.status().starts_with("Gone"));
    match up.request("ping", None, 500) {
        Err(UpstreamError::Unavailable(why)) => {
            assert!(why.contains("will not be restarted"), "{why}")
        }
        other => panic!("{other:?}"),
    }
    assert!(up.info().is_err());
    assert_eq!(spawner.spawn_count(), 1);
    up.shutdown();
}

#[test]
fn the_restart_limit_ends_in_a_final_state() {
    // the first start works, every later start dies at once
    let spawner = ScriptedSpawner::new(|n| {
        if n == 0 {
            Ok(mcp_behavior(&["crash"]))
        } else {
            Ok(Box::new(|_: &Value| vec![ChildAction::Exit { clean: false }]) as Behavior)
        }
    });
    let up = start(spawner.clone(), settings(RestartMode::OnFailure, 2, 8))
        .0
        .unwrap();
    let _ = up.request("tools/call", Some(call_params("crash", "{}")), 3000);
    wait_for("giving up", || up.status().starts_with("Gone"));
    assert_eq!(spawner.spawn_count(), 3, "one start and two restarts");
    up.shutdown();
}

#[test]
fn a_child_that_does_not_answer_the_handshake_fails_the_start() {
    let spawner = ScriptedSpawner::always(|| Box::new(|_: &Value| vec![]));
    let mut s = settings(RestartMode::Never, 0, 8);
    s.startup_timeout_ms = 200;
    let (up, log) = start(spawner, s);
    assert!(up.is_err());
    assert!(log.contains("handshake failed"));
}

#[test]
fn a_child_with_a_broken_initialize_answer_fails_the_start() {
    let spawner = ScriptedSpawner::always(|| {
        Box::new(|msg: &Value| match msg.get("id") {
            Some(id) => vec![ChildAction::Say(
                jsonrpc::response_ok(id, Value::str("garbage")).to_json(),
            )],
            None => vec![],
        })
    });
    let (up, _) = start(spawner, settings(RestartMode::Never, 0, 8));
    assert!(up.is_err());
}

#[test]
fn a_child_that_cannot_be_spawned_fails_the_start() {
    let spawner = ScriptedSpawner::new(|_| Err("no such program".into()));
    let (up, log) = start(spawner, settings(RestartMode::Never, 0, 8));
    assert!(up.err().unwrap().contains("could not be started"));
    assert!(log.contains("no such program"));
}

#[test]
fn rubbish_from_the_child_is_counted_and_does_not_disturb_the_session() {
    let spawner = ScriptedSpawner::always(|| {
        let mut inner = mcp_behavior(&["t"]);
        Box::new(move |msg: &Value| {
            let mut out = Vec::new();
            if msg.get("method").and_then(Value::as_str) == Some("ping") {
                out.push(ChildAction::Say("this is not json \u{1b}[2J".into()));
                out.push(ChildAction::Say(r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}"#.into()));
                out.push(ChildAction::Say(
                    r#"{"jsonrpc":"2.0","id":777,"result":{}}"#.into(),
                ));
                out.push(ChildAction::Say(
                    r#"{"jsonrpc":"2.0","id":"str","result":{}}"#.into(),
                ));
                out.push(ChildAction::Say(
                    r#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#.into(),
                ));
                out.push(ChildAction::Say(
                    r#"{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage"}"#.into(),
                ));
                out.push(ChildAction::Say(
                    r#"{"jsonrpc":"2.0","id":6,"method":"ping"}"#.into(),
                ));
            }
            out.extend(inner(msg));
            out
        })
    });
    let (up, log) = start(spawner.clone(), settings(RestartMode::Never, 0, 8));
    let up = up.unwrap();
    assert!(up.request("ping", None, 2000).is_ok());
    wait_for("the counters", || up.stats().child_requests == 2);
    let stats = up.stats();
    assert_eq!(stats.invalid_lines, 2);
    assert_eq!(stats.ignored_notifications, 1);
    assert_eq!(stats.late_responses, 2);
    assert!(log.contains("not a JSON-RPC message") && !log.contains('\u{1b}'.to_string().as_str()));
    // the gateway answered the child's own requests: an error for sampling, a result for ping
    wait_for("the answers to the child", || {
        let r = spawner.received();
        r.iter()
            .any(|l| l.contains("\"id\":5") && l.contains("error"))
            && r.iter()
                .any(|l| l.contains("\"id\":6") && l.contains("result"))
    });
    up.shutdown();
}

#[test]
fn an_oversized_answer_fails_its_call_at_once() {
    let spawner = ScriptedSpawner::always(|| {
        let mut inner = mcp_behavior(&["big"]);
        Box::new(move |msg: &Value| {
            let is_big = msg
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                == Some("big");
            if is_big {
                let id = msg.get("id").map(Value::to_json).unwrap_or_default();
                let head = format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{"content":[{{"type":"text","text":"xxxx"#).into_bytes();
                return vec![ChildAction::Event(Read::Line(Line::Oversize {
                    head,
                    len: 50_000_000,
                }))];
            }
            inner(msg)
        })
    });
    let up = start(spawner, settings(RestartMode::Never, 0, 8))
        .0
        .unwrap();
    let started = Instant::now();
    assert_eq!(
        up.request("tools/call", Some(call_params("big", "{}")), 5000),
        Err(UpstreamError::TooLarge)
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(up.stats().oversized_lines, 1);
    up.shutdown();
}

#[test]
fn shutdown_fails_waiting_calls_and_later_ones() {
    let up = Arc::new(
        start(well_behaved(), settings(RestartMode::Always, 5, 8))
            .0
            .unwrap(),
    );
    let waiter = {
        let up = Arc::clone(&up);
        std::thread::spawn(move || {
            up.request("tools/call", Some(call_params("slow", "{}")), 10_000)
        })
    };
    std::thread::sleep(Duration::from_millis(150));
    up.shutdown();
    assert!(matches!(
        waiter.join().unwrap(),
        Err(UpstreamError::Unavailable(_))
    ));
    assert!(matches!(
        up.request("ping", None, 100),
        Err(UpstreamError::Unavailable(_))
    ));
    assert_eq!(up.status(), "Stopped");
    up.shutdown();
}

#[test]
fn an_oversized_line_with_an_id_deep_inside_does_not_fail_another_call() {
    // the child answers the call to "big" with an oversized line whose result comes first and holds
    // the id of the call that is waiting in "slow": only the timeout of each may end them
    let spawner = ScriptedSpawner::always(|| {
        let mut inner = mcp_behavior(&["slow", "big"]);
        Box::new(move |msg: &Value| {
            let is_big = msg
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                == Some("big");
            if is_big {
                // gateway ids: 1 is the handshake, 2 the call to "slow", 3 this call
                let head =
                    br#"{"jsonrpc":"2.0","result":{"structuredContent":{"id":2,"rows":[1,2,3"#
                        .to_vec();
                return vec![ChildAction::Event(Read::Line(Line::Oversize {
                    head,
                    len: 9_000_000,
                }))];
            }
            inner(msg)
        })
    });
    let up = Arc::new(
        start(spawner, settings(RestartMode::Never, 0, 8))
            .0
            .unwrap(),
    );
    let slow = {
        let up = Arc::clone(&up);
        std::thread::spawn(move || up.request("tools/call", Some(call_params("slow", "{}")), 900))
    };
    std::thread::sleep(Duration::from_millis(150));
    let big = up.request("tools/call", Some(call_params("big", "{}")), 300);
    assert_eq!(
        big,
        Err(UpstreamError::Timeout),
        "a line that cannot be matched is dropped and the timeout applies"
    );
    assert_eq!(
        slow.join().unwrap(),
        Err(UpstreamError::Timeout),
        "the other call ends by its own timeout, not with a too-large error"
    );
    assert_eq!(up.stats().oversized_lines, 1);
    up.shutdown();
}
