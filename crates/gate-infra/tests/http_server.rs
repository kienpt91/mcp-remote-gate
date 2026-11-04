//! The HTTP server over real loopback sockets: well-formed traffic, keep-alive and pipelining,
//! and hostile requests (smuggling, oversized heads and bodies, slow clients, garbage).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gate_app::gateway::{Request, Response};
use gate_app::testing::VecLogger;
use gate_infra::http::{Handler, HttpLimits, HttpServer};
use gate_infra::httpclient::{exchange_raw, parse_response, request, ClientResponse};

struct Rig {
    server: HttpServer,
    addr: SocketAddr,
    calls: Arc<AtomicUsize>,
    log: Arc<VecLogger>,
}

fn rig_with(limits: HttpLimits) -> Rig {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let handler: Handler = Arc::new(move |req: &Request| {
        counter.fetch_add(1, Ordering::SeqCst);
        let body = format!(
            "{{\"method\":\"{:?}\",\"path\":\"{}\",\"host\":\"{}\",\"auth\":\"{}\",\"len\":{},\"peer\":\"{}\"}}",
            req.method,
            req.path,
            req.host.clone().unwrap_or_default(),
            req.authorization.clone().unwrap_or_default(),
            req.body.len(),
            req.peer.clone().unwrap_or_default()
        );
        Response {
            status: 200,
            body: body.into_bytes(),
            retry_after_secs: None,
            allow: None,
            challenge: false,
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let log = Arc::new(VecLogger::default());
    let server = HttpServer::start(listener, limits, handler, log.clone()).unwrap();
    let addr = server.local_addr();
    Rig {
        server,
        addr,
        calls,
        log,
    }
}

fn limits() -> HttpLimits {
    HttpLimits::new(1024, 600, 600, 16)
}

fn rig() -> Rig {
    rig_with(limits())
}

fn get(addr: SocketAddr, raw: &str) -> Option<ClientResponse> {
    parse_response(&exchange_raw(addr, raw.as_bytes(), Duration::from_secs(5)).unwrap())
}

#[test]
fn a_post_reaches_the_handler_with_its_parts() {
    let r = rig();
    let resp = request(
        r.addr,
        "POST",
        "/mcp?ignored=1",
        &[
            ("Authorization", "Bearer t"),
            ("Content-Type", "application/json"),
        ],
        b"{\"a\":1}",
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(resp.status, 200);
    let text = resp.text();
    for expected in [
        "\"method\":\"Post\"",
        "\"path\":\"/mcp\"",
        "\"auth\":\"Bearer t\"",
        "\"len\":7",
        "\"peer\":\"127.0.0.1\"",
    ] {
        assert!(text.contains(expected), "{expected} not in {text}");
    }
    assert_eq!(resp.header("content-type"), Some("application/json"));
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    assert_eq!(resp.header("x-content-type-options"), Some("nosniff"));
    assert!(
        resp.header("server").is_none(),
        "the server does not announce itself"
    );
    assert_eq!(r.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn keep_alive_and_pipelining_serve_every_request_in_order() {
    let r = rig();
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let one = format!(
        "POST /one HTTP/1.1\r\nHost: {}\r\nContent-Length: 3\r\n\r\nabc",
        r.addr
    );
    let two = format!(
        "GET /two HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        r.addr
    );
    s.write_all(format!("{one}{two}").as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let first = out.find("/one").unwrap();
    let second = out.find("/two").unwrap();
    assert!(first < second, "{out}");
    assert_eq!(out.matches("HTTP/1.1 200 OK").count(), 2);
    assert_eq!(r.calls.load(Ordering::SeqCst), 2);
    assert!(out.contains("Connection: keep-alive") && out.contains("Connection: close"));
}

#[test]
fn a_second_request_on_the_same_connection_after_the_first_answer() {
    let r = rig();
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    for i in 0..3 {
        s.write_all(format!("GET /r{i} HTTP/1.1\r\nHost: {}\r\n\r\n", r.addr).as_bytes())
            .unwrap();
        let mut buf = [0u8; 4096];
        let n = s.read(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(
            text.starts_with("HTTP/1.1 200") && text.contains(&format!("/r{i}")),
            "{text}"
        );
    }
}

#[test]
fn transfer_encoding_cannot_smuggle_a_second_request() {
    let r = rig();
    let host = r.addr;
    let smuggled = format!("GET /smuggled HTTP/1.1\r\nHost: {host}\r\n\r\n");
    let raw = format!(
        "POST /mcp HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n{smuggled}",
        5 + smuggled.len()
    );
    let resp = get(r.addr, &raw).unwrap();
    assert_eq!(resp.status, 501);
    assert_eq!(resp.header("connection"), Some("close"));
    assert_eq!(
        r.calls.load(Ordering::SeqCst),
        0,
        "neither request reached the handler"
    );
}

#[test]
fn conflicting_content_lengths_are_refused() {
    let r = rig();
    let raw = format!(
        "POST /mcp HTTP/1.1\r\nHost: {}\r\nContent-Length: 3\r\nContent-Length: 30\r\n\r\nabc",
        r.addr
    );
    assert_eq!(get(r.addr, &raw).unwrap().status, 400);
    let raw = format!(
        "POST /mcp HTTP/1.1\r\nHost: {}\r\nContent-Length: 3, 30\r\n\r\nabc",
        r.addr
    );
    assert_eq!(get(r.addr, &raw).unwrap().status, 400);
    assert_eq!(r.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn lf_only_and_folded_requests_are_refused() {
    let r = rig();
    // a head that ends in a bare LF never completes, so it is answered with a timeout
    let resp = get(r.addr, &format!("GET / HTTP/1.1\nHost: {}\n\n", r.addr)).unwrap();
    assert_eq!(resp.status, 408);
    assert_eq!(
        get(
            r.addr,
            &format!("GET / HTTP/1.1\r\nHost: {}\r\n X: folded\r\n\r\n", r.addr)
        )
        .unwrap()
        .status,
        400
    );
    assert_eq!(
        get(
            r.addr,
            &format!("GET / HTTP/1.1\r\nHost: {}\rX: y\r\n\r\n", r.addr)
        )
        .unwrap()
        .status,
        400
    );
    assert_eq!(r.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn oversized_heads_are_refused_with_431() {
    let r = rig();
    let big = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nX-Big: {}\r\n\r\n",
        r.addr,
        "a".repeat(20_000)
    );
    assert_eq!(get(r.addr, &big).unwrap().status, 431);
    let endless = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nX-Big: {}",
        r.addr,
        "a".repeat(40_000)
    );
    assert_eq!(
        get(r.addr, &endless).unwrap().status,
        431,
        "a head without an end is cut at the limit"
    );
    let many: String = (0..100).map(|i| format!("X-{i}: v\r\n")).collect();
    assert_eq!(
        get(
            r.addr,
            &format!("GET / HTTP/1.1\r\nHost: {}\r\n{many}\r\n", r.addr)
        )
        .unwrap()
        .status,
        431
    );
    assert_eq!(r.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn an_oversized_body_is_refused_before_it_is_read() {
    let r = rig();
    let started = Instant::now();
    let raw = format!(
        "POST /mcp HTTP/1.1\r\nHost: {}\r\nContent-Length: 10000000\r\n\r\n",
        r.addr
    );
    assert_eq!(get(r.addr, &raw).unwrap().status, 413);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the server must not wait for the body"
    );
    assert_eq!(r.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_post_without_a_length_and_old_versions_are_refused() {
    let r = rig();
    assert_eq!(
        get(
            r.addr,
            &format!("POST /mcp HTTP/1.1\r\nHost: {}\r\n\r\n", r.addr)
        )
        .unwrap()
        .status,
        411
    );
    assert_eq!(
        get(
            r.addr,
            &format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", r.addr)
        )
        .unwrap()
        .status,
        505
    );
    assert_eq!(
        get(r.addr, "GET / HTTP/1.1\r\n\r\n").unwrap().status,
        400,
        "Host is required"
    );
    assert_eq!(
        get(
            r.addr,
            &format!("GET http://evil/ HTTP/1.1\r\nHost: {}\r\n\r\n", r.addr)
        )
        .unwrap()
        .status,
        400
    );
}

#[test]
fn a_slow_head_is_cut_off_at_the_deadline() {
    let r = rig();
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let started = Instant::now();
    let _ = s.write_all(b"POST /mcp HTTP/1.1\r\n");
    // one byte every 100 ms never completes a head within 600 ms
    for byte in b"Host: x\r\nX-Slow: yyyyyyyyyyyyyyyy" {
        std::thread::sleep(Duration::from_millis(100));
        if s.write_all(&[*byte]).is_err() {
            break;
        }
    }
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 408"), "{out:?}");
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(r.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_slow_body_is_cut_off_too() {
    let r = rig();
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(
        format!(
            "POST /mcp HTTP/1.1\r\nHost: {}\r\nContent-Length: 100\r\n\r\nabc",
            r.addr
        )
        .as_bytes(),
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 408"), "{out:?}");
    assert_eq!(r.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_connection_that_sends_nothing_is_dropped() {
    let r = rig();
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 16];
    assert_eq!(s.read(&mut buf).unwrap_or(0), 0);
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn an_idle_keep_alive_connection_is_closed() {
    let r = rig();
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(format!("GET /a HTTP/1.1\r\nHost: {}\r\n\r\n", r.addr).as_bytes())
        .unwrap();
    let mut buf = [0u8; 4096];
    assert!(s.read(&mut buf).unwrap() > 0);
    let started = Instant::now();
    assert_eq!(
        s.read(&mut buf).unwrap_or(0),
        0,
        "the server closes an idle connection"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn expect_continue_gets_an_interim_response() {
    let r = rig();
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(
        format!("POST /mcp HTTP/1.1\r\nHost: {}\r\nContent-Length: 4\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n", r.addr).as_bytes(),
    )
    .unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 100 Continue"));
    s.write_all(b"data").unwrap();
    let mut rest = String::new();
    s.read_to_string(&mut rest).unwrap();
    assert!(
        rest.starts_with("HTTP/1.1 200") && rest.contains("\"len\":4"),
        "{rest}"
    );
    let bad = format!(
        "POST /mcp HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nExpect: nonsense\r\n\r\n",
        r.addr
    );
    assert_eq!(get(r.addr, &bad).unwrap().status, 417);
}

#[test]
fn head_requests_get_no_body() {
    let r = rig();
    let raw = exchange_raw(
        r.addr,
        format!(
            "HEAD /x HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            r.addr
        )
        .as_bytes(),
        Duration::from_secs(5),
    )
    .unwrap();
    let resp = parse_response(&raw).unwrap();
    assert!(resp.body.is_empty() && resp.header("content-length").is_some());
}

#[test]
fn the_connection_limit_answers_503() {
    let r = rig_with(HttpLimits::new(1024, 5000, 5000, 2));
    let _a = TcpStream::connect(r.addr).unwrap();
    let _b = TcpStream::connect(r.addr).unwrap();
    for _ in 0..100 {
        if r.server.active_connections() == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut c = TcpStream::connect(r.addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 503"), "{out:?}");
    assert!(out.contains("Retry-After: 1"));
}

#[test]
fn garbage_does_not_hurt_the_server() {
    let r = rig();
    let mut x = 0xdead_beef_cafe_f00du64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for round in 0..40 {
        let len = (next() % 300) as usize;
        let mut bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if round % 3 == 0 {
            bytes.extend_from_slice(b"\r\n\r\n");
        }
        let _ = exchange_raw(r.addr, &bytes, Duration::from_millis(900));
    }
    assert_eq!(r.calls.load(Ordering::SeqCst), 0);
    let ok = request(
        r.addr,
        "GET",
        "/still-works",
        &[],
        b"",
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(ok.status, 200);
}

#[test]
fn a_client_that_disconnects_mid_body_does_not_reach_the_handler() {
    let r = rig();
    {
        let mut s = TcpStream::connect(r.addr).unwrap();
        s.write_all(
            format!(
                "POST /mcp HTTP/1.1\r\nHost: {}\r\nContent-Length: 50\r\n\r\nabc",
                r.addr
            )
            .as_bytes(),
        )
        .unwrap();
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(r.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn many_clients_at_once() {
    let r = rig_with(HttpLimits::new(1024, 5000, 5000, 64));
    let addr = r.addr;
    let handles: Vec<_> = (0..40)
        .map(|i| {
            std::thread::spawn(move || {
                let resp = request(
                    addr,
                    "POST",
                    &format!("/n{i}"),
                    &[],
                    format!("body{i}").as_bytes(),
                    Duration::from_secs(10),
                )
                .unwrap();
                assert_eq!(resp.status, 200);
                assert!(resp.text().contains(&format!("/n{i}")));
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(r.calls.load(Ordering::SeqCst), 40);
}

#[test]
fn stop_drains_and_closes_the_port() {
    let r = rig();
    let addr = r.addr;
    let calls = Arc::clone(&r.calls);
    let _idle = TcpStream::connect(addr).unwrap();
    assert_eq!(
        request(addr, "GET", "/x", &[], b"", Duration::from_secs(5))
            .unwrap()
            .status,
        200
    );
    let started = Instant::now();
    let left = r.server.stop(Duration::from_secs(5));
    assert_eq!(left, 0, "an idle connection does not hold the shutdown");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(
        TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_err(),
        "the port is closed"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn refused_requests_are_logged_at_a_limited_rate() {
    let r = rig();
    for _ in 0..30 {
        let _ = get(r.addr, "GET / HTTP/1.0\r\n\r\n");
    }
    let logged = r
        .log
        .lines()
        .iter()
        .filter(|(_, m)| m.contains("refused a request"))
        .count();
    assert!((1..=10).contains(&logged), "{logged}");
}
