//! Tests of the gateway request handler with fakes for every port.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::net::SocketAddr;
use std::sync::Arc;

use gate_domain::audit::Outcome;
use gate_domain::auth::{token_from_entropy, Authenticator, Scope, TokenEntry, TokenHash, TokenId};
use gate_domain::glob::Glob;
use gate_domain::hostcheck::{loopback_hosts, HostPolicy};
use gate_domain::json::{self, Value};
use gate_domain::jsonrpc;
use gate_domain::policy::{default_read_patterns, ArgRule, ToolPolicy};

use crate::gateway::{Gateway, GatewayConfig, HttpMethod, Ports, Request, Response};
use crate::testing::{FakeClock, FakeUpstream, FlagKillSwitch, MemoryAudit, VecLogger};
use crate::upstream::UpstreamError;

struct Rig {
    gateway: Gateway,
    upstream: Arc<FakeUpstream>,
    clock: Arc<FakeClock>,
    audit: Arc<MemoryAudit>,
    kill: Arc<FlagKillSwitch>,
    log: Arc<VecLogger>,
    full_token: String,
    read_token: String,
    narrow_token: String,
}

fn globs(patterns: &[&str]) -> Vec<Glob> {
    patterns.iter().map(|p| Glob::new(p).unwrap()).collect()
}

fn entry(id: &str, token: &str, scopes: Vec<Scope>, tools: Option<&[&str]>) -> TokenEntry {
    TokenEntry {
        id: TokenId::new(id).unwrap(),
        hash: TokenHash::of_token(token),
        scopes,
        tools: tools.map(globs),
    }
}

fn config() -> GatewayConfig {
    let addr: SocketAddr = "127.0.0.1:8787".parse().unwrap();
    GatewayConfig {
        endpoint: "/mcp".into(),
        hosts: HostPolicy::new(loopback_hosts(addr), vec![]),
        max_request_bytes: 4096,
        request_timeout_ms: 1000,
        requests_per_minute: 600,
        burst: 50,
        failed_auth_per_minute: 5,
        result_max_bytes: None,
        tool_result_prefix: None,
        log_arguments: false,
        arguments_max_chars: 200,
        gate_version: "0.0.0-test".into(),
    }
}

fn policy() -> ToolPolicy {
    ToolPolicy {
        allow: globs(&["*"]),
        deny: vec![],
        read_only: true,
        read_patterns: default_read_patterns(),
        rules: vec![],
    }
}

fn rig_with(cfg: GatewayConfig, policy: ToolPolicy, upstream: FakeUpstream) -> Rig {
    rig_with_audit(cfg, policy, upstream, Arc::new(MemoryAudit::new()))
}

fn rig_with_audit(
    cfg: GatewayConfig,
    policy: ToolPolicy,
    upstream: FakeUpstream,
    audit: Arc<MemoryAudit>,
) -> Rig {
    let (full, read, narrow) = (
        token_from_entropy(&[1; 32]),
        token_from_entropy(&[2; 32]),
        token_from_entropy(&[3; 32]),
    );
    let auth = Authenticator::new(vec![
        entry(
            "full",
            &full,
            vec![Scope::ToolsList, Scope::ToolsCall],
            None,
        ),
        entry("listonly", &read, vec![Scope::ToolsList], None),
        entry(
            "narrow",
            &narrow,
            vec![Scope::ToolsList, Scope::ToolsCall],
            Some(&["get_chats"]),
        ),
    ]);
    let upstream = Arc::new(upstream);
    let clock = Arc::new(FakeClock::new());
    let kill = Arc::new(FlagKillSwitch::default());
    let log = Arc::new(VecLogger::default());
    let ports = Ports {
        upstream: upstream.clone(),
        clock: clock.clone(),
        audit: audit.clone(),
        kill: kill.clone(),
        log: log.clone(),
    };
    Rig {
        gateway: Gateway::new(cfg, auth, policy, ports),
        upstream,
        clock,
        audit,
        kill,
        log,
        full_token: full,
        read_token: read,
        narrow_token: narrow,
    }
}

fn rig() -> Rig {
    rig_with(
        config(),
        policy(),
        FakeUpstream::with_tools(&["get_chats", "list_messages", "send_message", "delete_chat"]),
    )
}

fn post(token: Option<&str>, body: &str) -> Request {
    Request {
        method: HttpMethod::Post,
        path: "/mcp".into(),
        host: Some("127.0.0.1:8787".into()),
        origin: None,
        authorization: token.map(|t| format!("Bearer {t}")),
        content_type: Some("application/json".into()),
        accept: Some("application/json, text/event-stream".into()),
        protocol_version: Some("2025-06-18".into()),
        body: body.as_bytes().to_vec(),
        peer: Some("127.0.0.1".into()),
    }
}

fn rpc(id: i64, method: &str, params: &str) -> String {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{method}\",\"params\":{params}}}")
}

fn call(name: &str, args: &str) -> String {
    rpc(
        1,
        "tools/call",
        &format!("{{\"name\":\"{name}\",\"arguments\":{args}}}"),
    )
}

fn body(r: &Response) -> Value {
    json::parse(std::str::from_utf8(&r.body).unwrap()).unwrap()
}

fn error_code(r: &Response) -> i64 {
    match body(r).get("error").and_then(|e| e.get("code")) {
        Some(Value::Number(n)) => n.parse().unwrap(),
        other => panic!(
            "no error code in {other:?}: {}",
            String::from_utf8_lossy(&r.body)
        ),
    }
}

fn tool_names(r: &Response) -> Vec<String> {
    let v = body(r);
    v.get("result")
        .unwrap()
        .get("tools")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.get("name").and_then(Value::as_str).unwrap().to_string())
        .collect()
}

#[test]
fn initialize_is_answered_by_the_gateway() {
    let r = rig();
    let resp = r.gateway.handle(&post(Some(&r.full_token), &rpc(1, "initialize", r#"{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}"#)));
    assert_eq!(resp.status, 200);
    let text = String::from_utf8(resp.body).unwrap();
    assert!(
        text.contains("\"protocolVersion\":\"2025-06-18\"")
            && text.contains("fake (via mcp-remote-gate)"),
        "{text}"
    );
    assert!(r.upstream.calls().is_empty(), "initialize is not forwarded");
}

#[test]
fn the_tool_list_shows_only_what_the_policy_allows() {
    let r = rig();
    let resp = r
        .gateway
        .handle(&post(Some(&r.full_token), &rpc(2, "tools/list", "{}")));
    assert_eq!(resp.status, 200);
    assert_eq!(tool_names(&resp), ["get_chats", "list_messages"]);
    let resp = r
        .gateway
        .handle(&post(Some(&r.narrow_token), &rpc(2, "tools/list", "{}")));
    assert_eq!(
        tool_names(&resp),
        ["get_chats"],
        "a token limited to one tool sees one tool"
    );
    let audit = r.audit.records();
    assert_eq!(audit.len(), 2);
    assert_eq!(
        (
            audit[0].method.as_str(),
            audit[0].outcome,
            audit[0].token.as_deref()
        ),
        ("tools/list", Outcome::Allowed, Some("full"))
    );
}

#[test]
fn the_cursor_is_forwarded_and_nothing_else() {
    let r = rig();
    r.gateway.handle(&post(
        Some(&r.full_token),
        &rpc(
            2,
            "tools/list",
            r#"{"cursor":"abc","_meta":{"x":1},"extra":true}"#,
        ),
    ));
    assert_eq!(
        r.upstream.calls()[0].1.as_ref().unwrap().to_json(),
        r#"{"cursor":"abc"}"#
    );
}

#[test]
fn an_allowed_call_reaches_the_server_with_a_rebuilt_request() {
    let r = rig();
    let resp = r.gateway.handle(&post(Some(&r.full_token), &rpc(9, "tools/call", r#"{"name":"get_chats","arguments":{"limit":2},"_meta":{"progressToken":"p"},"extra":1}"#)));
    assert_eq!(resp.status, 200);
    assert_eq!(
        body(&resp).get("id"),
        Some(&Value::int(9)),
        "the id of the client is restored"
    );
    let params = r.upstream.tool_calls().remove(0);
    assert_eq!(
        params.unwrap().to_json(),
        r#"{"name":"get_chats","arguments":{"limit":2}}"#
    );
}

#[test]
fn a_denied_tool_never_reaches_the_server_and_is_audited() {
    let r = rig();
    let resp = r.gateway.handle(&post(
        Some(&r.full_token),
        &call("send_message", r#"{"to":"alice","text":"top secret"}"#),
    ));
    assert_eq!(resp.status, 200);
    assert_eq!(error_code(&resp), jsonrpc::FORBIDDEN);
    assert!(r.upstream.calls().is_empty());
    let rec = &r.audit.records()[0];
    assert_eq!(
        (
            rec.outcome,
            rec.reason.as_str(),
            rec.tool.as_deref(),
            rec.token.as_deref()
        ),
        (
            Outcome::Denied,
            "read_only",
            Some("send_message"),
            Some("full")
        )
    );
    assert!(
        rec.arguments.is_none(),
        "argument values are not logged by default"
    );
    assert!(!rec.to_line().contains("top secret"));
}

#[test]
fn switching_read_only_off_enables_sending() {
    let mut p = policy();
    p.read_only = false;
    let r = rig_with(config(), p, FakeUpstream::with_tools(&["send_message"]));
    let resp = r
        .gateway
        .handle(&post(Some(&r.full_token), &call("send_message", "{}")));
    assert!(body(&resp).get("result").is_some());
    assert_eq!(r.upstream.tool_calls().len(), 1);
}

#[test]
fn tools_that_are_not_listed_cannot_be_called_either() {
    let r = rig();
    for tool in ["delete_chat", "unknown_tool", "send_message"] {
        let resp = r
            .gateway
            .handle(&post(Some(&r.full_token), &call(tool, "{}")));
        assert_eq!(error_code(&resp), jsonrpc::FORBIDDEN, "{tool}");
    }
    // allowed by name, but the token is limited to another tool
    let resp = r
        .gateway
        .handle(&post(Some(&r.narrow_token), &call("list_messages", "{}")));
    assert_eq!(error_code(&resp), jsonrpc::FORBIDDEN);
    assert_eq!(r.audit.records().last().unwrap().reason, "token_tools");
    assert!(r.upstream.calls().is_empty());
}

#[test]
fn scopes_are_enforced() {
    let r = rig();
    let resp = r
        .gateway
        .handle(&post(Some(&r.read_token), &call("get_chats", "{}")));
    assert_eq!(error_code(&resp), jsonrpc::FORBIDDEN);
    assert_eq!(r.audit.records()[0].reason, "scope_missing");
    let mut scopes_only_call = rig();
    scopes_only_call.gateway = rig().gateway;
    let resp = r
        .gateway
        .handle(&post(Some(&r.read_token), &rpc(1, "tools/list", "{}")));
    assert_eq!(tool_names(&resp).len(), 2);
}

#[test]
fn argument_rules_are_enforced_before_the_call() {
    let mut p = policy();
    p.read_only = false;
    p.rules = vec![ArgRule {
        tool: Glob::new("send_*").unwrap(),
        max_arg_bytes: Some(60),
        max_string_len: Some(20),
        forbid_values: globs(&["*://*"]),
    }];
    let r = rig_with(config(), p, FakeUpstream::with_tools(&["send_message"]));
    let ok = r.gateway.handle(&post(
        Some(&r.full_token),
        &call("send_message", r#"{"text":"hi"}"#),
    ));
    assert!(body(&ok).get("result").is_some());
    for (args, reason) in [
        (
            r#"{"text":"see http://evil.example"}"#,
            "argument_string_too_long",
        ),
        (r#"{"u":"a://b"}"#, "argument_forbidden"),
        (
            r#"{"a":"1","b":"2","c":"3","d":"4","e":"5","f":"6","g":"7","h":"8","i":"9"}"#,
            "arguments_too_large",
        ),
    ] {
        let resp = r
            .gateway
            .handle(&post(Some(&r.full_token), &call("send_message", args)));
        assert_eq!(error_code(&resp), jsonrpc::FORBIDDEN, "{args}");
        assert_eq!(r.audit.records().last().unwrap().reason, reason);
        assert!(
            !String::from_utf8_lossy(&resp.body).contains("evil.example"),
            "the refused value is not echoed"
        );
    }
    assert_eq!(r.upstream.tool_calls().len(), 1);
}

#[test]
fn arguments_are_logged_only_on_request_and_redacted() {
    let mut cfg = config();
    cfg.log_arguments = true;
    let mut p = policy();
    p.read_only = false;
    let r = rig_with(cfg, p, FakeUpstream::with_tools(&["send_message"]));
    let secret = format!("sk-{}", "aB3dE5gH7jK9".repeat(4));
    r.gateway.handle(&post(
        Some(&r.full_token),
        &call(
            "send_message",
            &format!("{{\"to\":\"alice\",\"api_key\":\"x\",\"note\":\"{secret}\"}}"),
        ),
    ));
    let logged = r.audit.records()[0].arguments.clone().unwrap();
    assert!(
        logged.contains("alice") && !logged.contains(&secret) && !logged.contains("\"x\""),
        "{logged}"
    );
    assert!(logged.contains("[redacted]"));
}

#[test]
fn authentication_failures() {
    let r = rig();
    let wrong = token_from_entropy(&[9; 32]);
    for (token, header) in [
        (None, None),
        (Some(wrong.as_str()), None),
        (None, Some("Basic abc")),
        (None, Some("Bearer")),
        (None, Some("Bearer a b")),
    ] {
        let mut req = post(token, &rpc(1, "ping", "{}"));
        if let Some(h) = header {
            req.authorization = Some(h.to_string());
        }
        let resp = r.gateway.handle(&req);
        assert_eq!(resp.status, 401, "{token:?} {header:?}");
        assert!(resp.challenge);
        assert!(!String::from_utf8_lossy(&resp.body).contains(&wrong));
    }
    for rec in r.audit.records() {
        assert!(rec.token.is_none() && rec.outcome == Outcome::Denied);
        let line = rec.to_line();
        assert!(
            !line.contains(&wrong),
            "a presented token is never written to the audit log"
        );
    }
    assert!(r.upstream.calls().is_empty());
}

#[test]
fn a_flood_of_bad_tokens_is_limited_without_locking_out_a_good_one() {
    let r = rig();
    let wrong = token_from_entropy(&[9; 32]);
    let statuses: Vec<u16> = (0..30)
        .map(|_| {
            r.gateway
                .handle(&post(Some(&wrong), &rpc(1, "ping", "{}")))
                .status
        })
        .collect();
    assert_eq!(statuses.iter().filter(|s| **s == 401).count(), 5);
    assert_eq!(statuses.iter().filter(|s| **s == 429).count(), 25);
    let good = r
        .gateway
        .handle(&post(Some(&r.full_token), &rpc(1, "ping", "{}")));
    assert_eq!(good.status, 200, "a valid token still works during a flood");
    r.clock.advance(60_000);
    assert_eq!(
        r.gateway
            .handle(&post(Some(&wrong), &rpc(1, "ping", "{}")))
            .status,
        401
    );
}

#[test]
fn unauthenticated_audit_lines_are_throttled_and_the_drop_count_is_reported() {
    let r = rig();
    for _ in 0..200 {
        r.gateway.handle(&post(None, &rpc(1, "ping", "{}")));
    }
    let n = r.audit.records().len();
    assert!(n <= 31, "{n}");
    r.clock.advance(120_000);
    r.gateway.handle(&post(None, &rpc(1, "ping", "{}")));
    let last = r.audit.records().last().unwrap().clone();
    assert!(last.suppressed >= 150, "{}", last.suppressed);
}

#[test]
fn rate_limits_are_per_token() {
    let mut cfg = config();
    cfg.requests_per_minute = 60;
    cfg.burst = 3;
    let r = rig_with(cfg, policy(), FakeUpstream::with_tools(&[]));
    let statuses: Vec<u16> = (0..5)
        .map(|_| {
            r.gateway
                .handle(&post(Some(&r.full_token), &rpc(1, "ping", "{}")))
                .status
        })
        .collect();
    assert_eq!(statuses, [200, 200, 200, 429, 429]);
    let limited = r
        .gateway
        .handle(&post(Some(&r.full_token), &rpc(1, "ping", "{}")));
    assert_eq!(limited.retry_after_secs, Some(1));
    assert_eq!(
        r.gateway
            .handle(&post(Some(&r.read_token), &rpc(1, "ping", "{}")))
            .status,
        200,
        "another token has its own bucket"
    );
    assert_eq!(
        r.audit
            .records()
            .iter()
            .filter(|rec| rec.reason == "rate_limited")
            .count(),
        3
    );
    r.clock.advance(1000);
    assert_eq!(
        r.gateway
            .handle(&post(Some(&r.full_token), &rpc(1, "ping", "{}")))
            .status,
        200
    );
}

#[test]
fn host_and_origin_checks_come_before_authentication() {
    let r = rig();
    let mut req = post(Some(&r.full_token), &rpc(1, "ping", "{}"));
    req.host = Some("evil.example:8787".into());
    assert_eq!(r.gateway.handle(&req).status, 403);
    req.host = None;
    assert_eq!(r.gateway.handle(&req).status, 403);
    let mut req = post(Some(&r.full_token), &rpc(1, "ping", "{}"));
    req.origin = Some("https://evil.example".into());
    assert_eq!(r.gateway.handle(&req).status, 403);
    assert_eq!(
        r.audit
            .records()
            .iter()
            .map(|r| r.reason.as_str())
            .collect::<Vec<_>>(),
        ["host_rejected", "host_rejected", "origin_rejected"]
    );
    // a valid token does not make a rebinding request acceptable
    assert!(r.audit.records().iter().all(|rec| rec.token.is_none()));
}

#[test]
fn the_kill_switch_answers_503_to_everyone_at_once() {
    let r = rig();
    r.kill.set(true);
    for token in [Some(r.full_token.as_str()), None] {
        let resp = r.gateway.handle(&post(token, &rpc(1, "ping", "{}")));
        assert_eq!(resp.status, 503);
        assert_eq!(resp.retry_after_secs, Some(30));
    }
    assert!(r.upstream.calls().is_empty());
    r.kill.set(false);
    assert_eq!(
        r.gateway
            .handle(&post(Some(&r.full_token), &rpc(1, "ping", "{}")))
            .status,
        200
    );
    assert_eq!(r.audit.records()[0].reason, "kill_switch");
}

#[test]
fn request_format_checks() {
    let r = rig();
    let t = r.full_token.clone();
    let mut req = post(Some(&t), &rpc(1, "ping", "{}"));
    req.path = "/other".into();
    assert_eq!(r.gateway.handle(&req).status, 404);
    for method in [
        HttpMethod::Get,
        HttpMethod::Delete,
        HttpMethod::Options,
        HttpMethod::Other,
    ] {
        let mut req = post(Some(&t), "");
        req.method = method;
        let resp = r.gateway.handle(&req);
        assert_eq!((resp.status, resp.allow), (405, Some("POST")));
    }
    let mut req = post(None, "");
    req.method = HttpMethod::Get;
    assert_eq!(
        r.gateway.handle(&req).status,
        401,
        "an unauthenticated GET learns nothing"
    );
    let mut req = post(Some(&t), &rpc(1, "ping", "{}"));
    req.content_type = Some("text/plain".into());
    assert_eq!(r.gateway.handle(&req).status, 415);
    req.content_type = None;
    assert_eq!(r.gateway.handle(&req).status, 415);
    let mut req = post(Some(&t), &rpc(1, "ping", "{}"));
    req.content_type = Some("Application/JSON; charset=utf-8".into());
    assert_eq!(r.gateway.handle(&req).status, 200);
    req.accept = Some("text/event-stream".into());
    assert_eq!(r.gateway.handle(&req).status, 406);
    req.accept = Some("*/*".into());
    assert_eq!(r.gateway.handle(&req).status, 200);
    req.protocol_version = Some("latest".into());
    assert_eq!(r.gateway.handle(&req).status, 400);
    let big = post(
        Some(&t),
        &format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{{\"x\":\"{}\"}}}}",
            "a".repeat(5000)
        ),
    );
    assert_eq!(r.gateway.handle(&big).status, 413);
}

#[test]
fn malformed_bodies_are_refused() {
    let r = rig();
    let t = r.full_token.clone();
    let cases: [(&str, i64); 6] = [
        ("{not json", jsonrpc::PARSE_ERROR),
        ("", jsonrpc::PARSE_ERROR),
        (
            r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}"#,
            jsonrpc::PARSE_ERROR,
        ),
        (
            r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
            jsonrpc::INVALID_REQUEST,
        ),
        (
            r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#,
            jsonrpc::INVALID_REQUEST,
        ),
        (
            r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
            jsonrpc::INVALID_REQUEST,
        ),
    ];
    for (text, code) in cases {
        let resp = r.gateway.handle(&post(Some(&t), text));
        assert_eq!(resp.status, 400, "{text}");
        assert_eq!(error_code(&resp), code, "{text}");
    }
    let mut req = post(Some(&t), "");
    req.body = vec![0xff, 0xfe, b'{'];
    assert_eq!(r.gateway.handle(&req).status, 400);
    assert!(r.upstream.calls().is_empty());
}

#[test]
fn notifications_and_responses_are_accepted_without_a_body() {
    let r = rig();
    for text in [
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":3,"result":{}}"#,
    ] {
        let resp = r.gateway.handle(&post(Some(&r.full_token), text));
        assert_eq!((resp.status, resp.body.len()), (202, 0), "{text}");
    }
    assert!(
        r.upstream.calls().is_empty(),
        "notifications are not forwarded"
    );
}

#[test]
fn methods_other_than_tools_are_not_available() {
    let r = rig();
    for method in [
        "resources/read",
        "prompts/get",
        "logging/setLevel",
        "completion/complete",
        "sampling/createMessage",
        "x",
    ] {
        let resp = r
            .gateway
            .handle(&post(Some(&r.full_token), &rpc(1, method, "{}")));
        assert_eq!(error_code(&resp), jsonrpc::METHOD_NOT_FOUND, "{method}");
    }
    assert!(r.upstream.calls().is_empty());
    assert!(r
        .audit
        .records()
        .iter()
        .all(|rec| rec.reason == "method_not_allowed" && rec.outcome == Outcome::Denied));
}

#[test]
fn bad_call_params() {
    let r = rig();
    for params in [
        r#"{}"#,
        r#"{"name":5}"#,
        r#"{"name":"a\nb"}"#,
        r#"{"name":"get_chats","arguments":[1]}"#,
        r#"[]"#,
    ] {
        let resp = r
            .gateway
            .handle(&post(Some(&r.full_token), &rpc(1, "tools/call", params)));
        assert_eq!(error_code(&resp), jsonrpc::INVALID_PARAMS, "{params}");
    }
    assert!(r.upstream.calls().is_empty());
}

#[test]
fn ids_of_any_json_type_that_json_rpc_allows_come_back_unchanged() {
    let r = rig();
    for id in [
        "\"abc\"",
        "0",
        "123456789012345678901234567890",
        "-5",
        "1.5",
    ] {
        let text = format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"ping\"}}");
        let resp = r.gateway.handle(&post(Some(&r.full_token), &text));
        assert_eq!(
            body(&resp).get("id"),
            Some(&json::parse(id).unwrap()),
            "{id}"
        );
    }
}

#[test]
fn results_get_a_label_and_a_size_cap() {
    let mut cfg = config();
    cfg.result_max_bytes = Some(1200);
    cfg.tool_result_prefix = Some("[untrusted tool output] ".into());
    let big = "x".repeat(10_000);
    let upstream = FakeUpstream::listing(&["get_chats"], move |_, _| {
        Ok(Value::object([(
            "content",
            Value::Array(vec![Value::object([
                ("type", Value::str("text")),
                ("text", Value::str(&big)),
            ])]),
        )]))
    });
    let r = rig_with(cfg, policy(), upstream);
    let resp = r
        .gateway
        .handle(&post(Some(&r.full_token), &call("get_chats", "{}")));
    let text = String::from_utf8(resp.body.clone()).unwrap();
    assert!(
        text.contains("[untrusted tool output] ") && text.contains("truncated"),
        "{}",
        &text[..200]
    );
    assert!(resp.body.len() <= 1200 + 100, "{}", resp.body.len());
    // a result with nothing to cut is refused
    let r = rig_with(
        GatewayConfig {
            result_max_bytes: Some(1024),
            ..config()
        },
        policy(),
        FakeUpstream::listing(&["get_chats"], |_, _| {
            Ok(Value::object([(
                "structuredContent",
                Value::String("y".repeat(5000)),
            )]))
        }),
    );
    let resp = r
        .gateway
        .handle(&post(Some(&r.full_token), &call("get_chats", "{}")));
    assert_eq!(error_code(&resp), jsonrpc::RESULT_TOO_LARGE);
    assert_eq!(r.audit.records().last().unwrap().outcome, Outcome::Error);
}

#[test]
fn upstream_failures_map_to_distinct_answers() {
    let cases: [(UpstreamError, u16, i64, &str); 5] = [
        (
            UpstreamError::Unavailable("gone".into()),
            503,
            jsonrpc::UPSTREAM_UNAVAILABLE,
            "upstream_unavailable",
        ),
        (UpstreamError::Busy, 429, jsonrpc::BUSY, "busy"),
        (
            UpstreamError::Timeout,
            200,
            jsonrpc::UPSTREAM_TIMEOUT,
            "timeout",
        ),
        (
            UpstreamError::TooLarge,
            200,
            jsonrpc::RESULT_TOO_LARGE,
            "result_too_large",
        ),
        (
            UpstreamError::Rpc(jsonrpc::RpcError {
                code: -32602,
                message: "bad \u{1b}[2J tool".into(),
                data: Some(Value::str("secret internals")),
            }),
            200,
            -32602,
            "upstream_error",
        ),
    ];
    for (error, status, code, reason) in cases {
        let e = error.clone();
        let r = rig_with(
            config(),
            policy(),
            FakeUpstream::new(move |_, _| Err(e.clone())),
        );
        let resp = r
            .gateway
            .handle(&post(Some(&r.full_token), &call("get_chats", "{}")));
        assert_eq!(
            (resp.status, error_code(&resp)),
            (status, code),
            "{error:?}"
        );
        assert_eq!(r.audit.records().last().unwrap().reason, reason);
        let text = String::from_utf8_lossy(&resp.body).into_owned();
        assert!(
            !text.contains("secret internals")
                && !text.contains('\u{1b}')
                && !text.contains("gone"),
            "{text}"
        );
    }
}

#[test]
fn initialize_without_an_upstream_is_503() {
    let r = rig();
    r.upstream
        .set_info(Err(UpstreamError::Unavailable("restarting".into())));
    let resp = r
        .gateway
        .handle(&post(Some(&r.full_token), &rpc(1, "initialize", "{}")));
    assert_eq!(resp.status, 503);
    assert!(r.log.contains("restarting"));
}

#[test]
fn when_the_audit_log_cannot_be_written_tool_calls_stop_but_the_rest_goes_on() {
    let mut p = policy();
    p.read_only = false;
    let r = rig_with(config(), p, FakeUpstream::with_tools(&["get_chats"]));
    r.audit.fail_writes(true);
    let resp = r
        .gateway
        .handle(&post(Some(&r.full_token), &call("get_chats", "{}")));
    assert_eq!(resp.status, 503);
    assert!(
        r.upstream.tool_calls().is_empty(),
        "no call runs without a trail"
    );
    assert_eq!(
        r.gateway
            .handle(&post(Some(&r.full_token), &rpc(1, "ping", "{}")))
            .status,
        200
    );
    assert!(r.log.contains("cannot write the audit log"));
    r.audit.fail_writes(false);
    assert!(body(
        &r.gateway
            .handle(&post(Some(&r.full_token), &call("get_chats", "{}")))
    )
    .get("result")
    .is_some());
}

#[test]
fn a_hostile_tool_name_cannot_forge_a_log_line() {
    let r = rig();
    let name = "get_x\\n{\\\"outcome\\\":\\\"allowed\\\"}\\u001b[2J";
    r.gateway.handle(&post(Some(&r.full_token), &format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"name\":\"{name}\"}}}}")));
    for rec in r.audit.records() {
        let line = rec.to_line();
        assert!(!line.contains('\n') && !line.contains('\u{1b}'));
    }
}

#[test]
fn property_arbitrary_bodies_never_crash_and_never_reach_the_server_by_accident() {
    let mut cfg = config();
    cfg.burst = 100_000;
    cfg.requests_per_minute = 100_000;
    let r = rig_with(
        cfg,
        policy(),
        FakeUpstream::with_tools(&["get_chats", "send_message"]),
    );
    let mut x = 0x7777_aaaa_5555_cccc_u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let pieces = [
        "{",
        "}",
        "[",
        "]",
        "\"",
        ":",
        ",",
        "\"jsonrpc\"",
        "\"2.0\"",
        "\"id\"",
        "1",
        "\"method\"",
        "\"tools/call\"",
        "\"tools/list\"",
        "\"params\"",
        "\"name\"",
        "\"send_message\"",
        "\"get_chats\"",
        "\"arguments\"",
        "null",
        "true",
        "\\u0000",
        " ",
        "\n",
        "é",
    ];
    for _ in 0..4000 {
        let text: String = (0..next() % 24)
            .map(|_| pieces[(next() % pieces.len() as u64) as usize])
            .collect();
        let resp = r.gateway.handle(&post(Some(&r.full_token), &text));
        assert!(
            matches!(resp.status, 200 | 202 | 400),
            "{text}: {}",
            resp.status
        );
    }
    for (method, params) in r.upstream.calls() {
        // only requests that passed every check were forwarded, and never a tool the policy denies
        assert!(method == "tools/list" || method == "tools/call");
        if method == "tools/call" {
            let name = params
                .as_ref()
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            assert_ne!(name, "send_message", "a denied tool reached the upstream");
        }
    }
}

#[test]
fn bidi_and_zero_width_characters_in_a_method_or_tool_name_do_not_reach_the_audit_file_raw() {
    let r = rig();
    let method = rpc(1, "x\\u202eevil\\u009b\\u200b", "{}");
    r.gateway.handle(&post(Some(&r.full_token), &method));
    let tool = call("get_chats\\u200b", "{}");
    let resp = r.gateway.handle(&post(Some(&r.full_token), &tool));
    assert_eq!(
        error_code(&resp),
        jsonrpc::INVALID_PARAMS,
        "a tool name with an invisible character is not a valid name"
    );
    assert!(r.upstream.calls().is_empty());
    for rec in r.audit.records() {
        let line = rec.to_line();
        assert!(
            !line.contains('\u{202e}') && !line.contains('\u{9b}') && !line.contains('\u{200b}'),
            "{line}"
        );
    }
    assert_eq!(r.audit.records().len(), 2);
}

#[test]
fn an_intent_record_is_on_disk_before_the_call_reaches_the_server() {
    let audit = Arc::new(MemoryAudit::new());
    let seen_by_the_server: Arc<std::sync::Mutex<Vec<gate_domain::audit::AuditRecord>>> =
        Arc::default();
    let (for_server, snapshot) = (Arc::clone(&audit), Arc::clone(&seen_by_the_server));
    let upstream = FakeUpstream::listing(&["get_chats"], move |_, _| {
        // what the audit log holds at the moment the server is asked
        *snapshot.lock().unwrap() = for_server.records();
        Ok(Value::object([(
            "content",
            Value::Array(vec![Value::object([
                ("type", Value::str("text")),
                ("text", Value::str("done")),
            ])]),
        )]))
    });
    let mut p = policy();
    p.read_only = false;
    let r = rig_with_audit(config(), p, upstream, audit);
    let resp = r.gateway.handle(&post(
        Some(&r.full_token),
        &call("get_chats", r#"{"limit":2}"#),
    ));
    assert_eq!(resp.status, 200);
    let during = seen_by_the_server.lock().unwrap().clone();
    assert_eq!(
        during.len(),
        1,
        "exactly the intent record exists while the call runs"
    );
    assert_eq!(during[0].outcome, Outcome::Started);
    assert_eq!(during[0].reason, "intent");
    assert_eq!(during[0].tool.as_deref(), Some("get_chats"));
    assert_eq!(during[0].token.as_deref(), Some("full"));
    assert_eq!(during[0].method, "tools/call");
    assert!(during[0].arguments.is_none());
    let all = r.audit.records();
    assert_eq!(
        all.iter().map(|rec| rec.outcome).collect::<Vec<_>>(),
        [Outcome::Started, Outcome::Allowed],
        "the completion record follows"
    );
}

#[test]
fn a_call_that_never_completes_still_leaves_its_intent() {
    // the server never answers: the call times out, and the trail shows the intent and the timeout
    let mut p = policy();
    p.read_only = false;
    let r = rig_with(
        config(),
        p,
        FakeUpstream::listing(&["get_chats"], |_, _| Err(UpstreamError::Timeout)),
    );
    r.gateway
        .handle(&post(Some(&r.full_token), &call("get_chats", "{}")));
    let outcomes: Vec<_> = r
        .audit
        .records()
        .iter()
        .map(|rec| (rec.outcome, rec.reason.clone()))
        .collect();
    assert_eq!(
        outcomes,
        [
            (Outcome::Started, "intent".to_string()),
            (Outcome::Error, "timeout".to_string())
        ]
    );
}

#[test]
fn the_first_failed_write_already_refuses_the_call() {
    // no earlier write failed: the intent write itself is what is checked
    let mut p = policy();
    p.read_only = false;
    let r = rig_with(config(), p, FakeUpstream::with_tools(&["get_chats"]));
    r.audit.fail_writes(true);
    let resp = r
        .gateway
        .handle(&post(Some(&r.full_token), &call("get_chats", "{}")));
    assert_eq!(resp.status, 503);
    assert_eq!(resp.retry_after_secs, Some(30));
    assert!(
        r.upstream.tool_calls().is_empty(),
        "the call never reached the server"
    );
    assert!(r.log.contains("cannot write the audit log"));
}

#[test]
fn requests_that_never_reach_the_server_have_a_single_record() {
    let r = rig();
    r.gateway
        .handle(&post(Some(&r.full_token), &call("send_message", "{}")));
    r.gateway
        .handle(&post(Some(&r.full_token), &rpc(2, "tools/list", "{}")));
    r.gateway
        .handle(&post(Some(&r.full_token), &rpc(3, "ping", "{}")));
    assert_eq!(r.audit.records().len(), 3);
    assert!(r
        .audit
        .records()
        .iter()
        .all(|rec| rec.outcome != Outcome::Started));
}

/// Locks without an unwrap: a poisoned lock still holds usable data in these tests.
fn locked<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// An upstream whose tool list can change, that records what it was asked, and that, like a server
/// which normalises names, would run \`Send_Message\` as \`send_message\`.
fn lenient_server(
    tools: Arc<std::sync::Mutex<Vec<String>>>,
    ran: Arc<std::sync::Mutex<Vec<String>>>,
    page_size: usize,
) -> FakeUpstream {
    FakeUpstream::new(move |method, params| match method {
        "tools/list" => {
            let all = locked(&tools).clone();
            let start = params
                .and_then(|p| p.get("cursor"))
                .and_then(Value::as_str)
                .and_then(|c| c.parse::<usize>().ok())
                .unwrap_or(0);
            let page: Vec<Value> = all
                .iter()
                .skip(start)
                .take(page_size)
                .map(|n| Value::object([("name", Value::str(n))]))
                .collect();
            let mut result = Value::object([("tools", Value::Array(page))]);
            if start + page_size < all.len() {
                result.set("nextCursor", Value::String((start + page_size).to_string()));
            }
            Ok(result)
        }
        "tools/call" => {
            let name = params
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            locked(&ran).push(name.to_lowercase());
            Ok(Value::object([(
                "content",
                Value::Array(vec![Value::object([
                    ("type", Value::str("text")),
                    ("text", Value::str("ran")),
                ])]),
            )]))
        }
        _ => Err(UpstreamError::Timeout),
    })
}

fn names(list: &[&str]) -> Arc<std::sync::Mutex<Vec<String>>> {
    Arc::new(std::sync::Mutex::new(
        list.iter().map(|s| (*s).to_string()).collect(),
    ))
}

fn deny_send_policy() -> ToolPolicy {
    ToolPolicy {
        allow: globs(&["*"]),
        deny: globs(&["send_*"]),
        read_only: false,
        read_patterns: default_read_patterns(),
        rules: vec![],
    }
}

#[test]
fn a_name_variant_that_dodges_the_denylist_is_not_forwarded() {
    // the server would run "Send_Message" as send_message, but it does not list that name
    let ran = names(&[]);
    let r = rig_with(
        config(),
        deny_send_policy(),
        lenient_server(names(&["send_message", "get_chats"]), ran.clone(), 100),
    );
    assert_eq!(
        error_code(
            &r.gateway
                .handle(&post(Some(&r.full_token), &call("send_message", "{}")))
        ),
        jsonrpc::FORBIDDEN,
        "the exact name is on the denylist"
    );
    for variant in ["Send_Message", "SEND_MESSAGE", "sEnd_messagE"] {
        let resp = r
            .gateway
            .handle(&post(Some(&r.full_token), &call(variant, "{}")));
        assert_eq!(error_code(&resp), jsonrpc::INVALID_PARAMS, "{variant}");
        assert_eq!(r.audit.records().last().unwrap().reason, "tool_not_listed");
    }
    assert!(
        locked(&ran).is_empty(),
        "no variant reached the server: {:?}",
        locked(&ran)
    );
    // a listed, allowed tool still works
    let ok = r
        .gateway
        .handle(&post(Some(&r.full_token), &call("get_chats", "{}")));
    assert!(body(&ok).get("result").is_some());
    assert_eq!(*locked(&ran), ["get_chats"]);
}

#[test]
fn the_tool_list_is_fetched_once_and_reused() {
    let ran = names(&[]);
    let r = rig_with(
        config(),
        deny_send_policy(),
        lenient_server(names(&["get_chats", "list_chats"]), ran, 100),
    );
    for _ in 0..5 {
        r.gateway
            .handle(&post(Some(&r.full_token), &call("get_chats", "{}")));
    }
    let lists = r
        .upstream
        .calls()
        .iter()
        .filter(|(m, _)| m == "tools/list")
        .count();
    assert_eq!(lists, 1);
}

#[test]
fn an_unknown_name_does_not_make_the_gateway_list_tools_again_and_again() {
    let ran = names(&[]);
    let tools = names(&["get_chats"]);
    let r = rig_with(
        config(),
        deny_send_policy(),
        lenient_server(tools.clone(), ran, 100),
    );
    let lists = |r: &Rig| {
        r.upstream
            .calls()
            .iter()
            .filter(|(m, _)| m == "tools/list")
            .count()
    };
    for _ in 0..20 {
        r.gateway
            .handle(&post(Some(&r.full_token), &call("nonexistent", "{}")));
    }
    assert_eq!(lists(&r), 1, "a burst of unknown names costs one listing");
    // a tool that appears later is found once the refresh interval has passed
    locked(&tools).push("new_tool".into());
    let resp = r
        .gateway
        .handle(&post(Some(&r.full_token), &call("new_tool", "{}")));
    assert_eq!(
        error_code(&resp),
        jsonrpc::INVALID_PARAMS,
        "too soon to look again"
    );
    r.clock.advance(6_000);
    let resp = r
        .gateway
        .handle(&post(Some(&r.full_token), &call("new_tool", "{}")));
    assert!(
        body(&resp).get("result").is_some(),
        "{}",
        String::from_utf8_lossy(&resp.body)
    );
    assert_eq!(lists(&r), 2);
}

#[test]
fn a_cached_list_expires() {
    let ran = names(&[]);
    let tools = names(&["get_chats", "old_tool"]);
    let r = rig_with(
        config(),
        deny_send_policy(),
        lenient_server(tools.clone(), ran.clone(), 100),
    );
    assert!(body(
        &r.gateway
            .handle(&post(Some(&r.full_token), &call("old_tool", "{}")))
    )
    .get("result")
    .is_some());
    locked(&tools).retain(|t| t != "old_tool");
    // still cached
    assert!(body(
        &r.gateway
            .handle(&post(Some(&r.full_token), &call("old_tool", "{}")))
    )
    .get("result")
    .is_some());
    r.clock.advance(61_000);
    let resp = r
        .gateway
        .handle(&post(Some(&r.full_token), &call("old_tool", "{}")));
    assert_eq!(
        error_code(&resp),
        jsonrpc::INVALID_PARAMS,
        "a removed tool is gone after the cache expired"
    );
}

#[test]
fn the_tool_list_is_read_across_pages() {
    let ran = names(&[]);
    let many: Vec<String> = (0..25).map(|i| format!("tool_{i}")).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    let r = rig_with(
        config(),
        deny_send_policy(),
        lenient_server(names(&refs), ran, 10),
    );
    let resp = r
        .gateway
        .handle(&post(Some(&r.full_token), &call("tool_24", "{}")));
    assert!(
        body(&resp).get("result").is_some(),
        "{}",
        String::from_utf8_lossy(&resp.body)
    );
    let lists = r
        .upstream
        .calls()
        .iter()
        .filter(|(m, _)| m == "tools/list")
        .count();
    assert_eq!(lists, 3);
}

#[test]
fn a_server_that_cannot_list_its_tools_means_no_call() {
    let r = rig_with(
        config(),
        deny_send_policy(),
        FakeUpstream::new(|_, _| Err(UpstreamError::Unavailable("gone".into()))),
    );
    let resp = r
        .gateway
        .handle(&post(Some(&r.full_token), &call("get_chats", "{}")));
    assert_eq!(resp.status, 503);
    assert!(
        r.audit
            .records()
            .iter()
            .all(|rec| rec.outcome != Outcome::Started),
        "no intent: the call was never forwarded"
    );
}

#[test]
fn the_listing_is_not_asked_for_a_tool_the_policy_already_refused() {
    let ran = names(&[]);
    let r = rig_with(
        config(),
        deny_send_policy(),
        lenient_server(names(&["send_message"]), ran, 100),
    );
    r.gateway
        .handle(&post(Some(&r.full_token), &call("send_message", "{}")));
    assert!(r.upstream.calls().is_empty());
}
