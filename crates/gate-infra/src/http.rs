//! A small HTTP/1.1 server on `std::net`, strict by design.
//!
//! The gateway needs POST with a JSON body and nothing else, so the parser accepts a narrow
//! language and refuses the rest, which removes most request-smuggling and parser-differential
//! tricks: CRLF line ends only, one space between the parts of the request line, no obsolete
//! line folding, no whitespace before a colon, no `Transfer-Encoding` at all (only
//! `Content-Length`, once, digits only), duplicate `Host`, `Authorization`, `Origin` and the other
//! headers the gateway reads are errors, and bodies are never decoded. Every read has a
//! deadline for the whole head and body, so a client that sends one byte a second is cut off.

use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use gate_app::gateway::{HttpMethod, Request, Response};
use gate_app::ports::{Level, Logger};
use gate_domain::sanitize::escape_control;

#[derive(Debug, Clone)]
pub struct HttpLimits {
    pub max_head_bytes: usize,
    pub max_headers: usize,
    pub max_body_bytes: usize,
    /// How long a client has to deliver a complete request (head and body) once it started.
    pub header_timeout: Duration,
    /// How long an idle keep-alive connection is kept.
    pub idle_timeout: Duration,
    pub write_timeout: Duration,
    pub max_connections: usize,
    pub max_requests_per_connection: usize,
}

impl HttpLimits {
    pub fn new(
        max_body_bytes: usize,
        header_timeout_ms: u64,
        idle_timeout_ms: u64,
        max_connections: usize,
    ) -> HttpLimits {
        HttpLimits {
            max_head_bytes: 16 * 1024,
            max_headers: 64,
            max_body_bytes,
            header_timeout: Duration::from_millis(header_timeout_ms),
            idle_timeout: Duration::from_millis(idle_timeout_ms),
            write_timeout: Duration::from_secs(10),
            max_connections,
            max_requests_per_connection: 100,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    BadRequest(&'static str),
    UriTooLong,
    HeadersTooLarge,
    NotImplemented(&'static str),
    VersionNotSupported,
    LengthRequired,
    PayloadTooLarge,
    ExpectationFailed,
    Timeout,
}

impl HttpError {
    pub fn status(&self) -> u16 {
        match self {
            HttpError::BadRequest(_) => 400,
            HttpError::Timeout => 408,
            HttpError::LengthRequired => 411,
            HttpError::PayloadTooLarge => 413,
            HttpError::UriTooLong => 414,
            HttpError::ExpectationFailed => 417,
            HttpError::HeadersTooLarge => 431,
            HttpError::NotImplemented(_) => 501,
            HttpError::VersionNotSupported => 505,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            HttpError::BadRequest(m) | HttpError::NotImplemented(m) => m,
            HttpError::Timeout => "timed out waiting for the request",
            HttpError::LengthRequired => "Content-Length is required",
            HttpError::PayloadTooLarge => "request too large",
            HttpError::UriTooLong => "request target too long",
            HttpError::ExpectationFailed => "unsupported Expect",
            HttpError::HeadersTooLarge => "request headers too large",
            HttpError::VersionNotSupported => "use HTTP/1.1",
        }
    }
}

/// The request line and the headers of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub method: String,
    pub target: String,
    /// Header names lowercased, values trimmed.
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn joined(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self
            .headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect();
        if values.is_empty() {
            None
        } else {
            Some(values.join(", "))
        }
    }
}

/// Headers that may appear only once.
const SINGLETONS: [&str; 8] = [
    "host",
    "content-length",
    "content-type",
    "authorization",
    "origin",
    "expect",
    "mcp-protocol-version",
    "transfer-encoding",
];

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn parse_request_line(line: &[u8]) -> Result<(String, String), HttpError> {
    let bad = HttpError::BadRequest("malformed request line");
    let text = std::str::from_utf8(line).map_err(|_| bad)?;
    let mut parts = text.splitn(3, ' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(bad);
    };
    if method.is_empty() || method.len() > 16 || !method.bytes().all(is_token_byte) {
        return Err(bad);
    }
    if version != "HTTP/1.1" {
        return Err(if version.starts_with("HTTP/") && !version.contains(' ') {
            HttpError::VersionNotSupported
        } else {
            bad
        });
    }
    if target.len() > 2048 {
        return Err(HttpError::UriTooLong);
    }
    if !target.starts_with('/')
        || target.contains('#')
        || !target.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(HttpError::BadRequest("unsupported request target"));
    }
    Ok((method.to_string(), target.to_string()))
}

fn parse_header_line(line: &[u8]) -> Result<(String, String), HttpError> {
    let bad = |m: &'static str| HttpError::BadRequest(m);
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(bad("obsolete line folding is not supported"));
    }
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or(bad("malformed header"))?;
    let (name, rest) = line.split_at(colon);
    if name.is_empty() || !name.iter().copied().all(is_token_byte) {
        return Err(bad("malformed header name"));
    }
    let value = rest.get(1..).unwrap_or_default();
    if value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(bad("control character in a header value"));
    }
    let value = std::str::from_utf8(value).map_err(|_| bad("header value is not valid UTF-8"))?;
    Ok((
        String::from_utf8_lossy(name).to_ascii_lowercase(),
        value.trim_matches(|c| c == ' ' || c == '\t').to_string(),
    ))
}

/// Parses the head of a request. `bytes` runs up to and including the empty line.
pub fn parse_head(bytes: &[u8], max_headers: usize) -> Result<Head, HttpError> {
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut rest = bytes;
    while let Some(at) = rest.windows(2).position(|w| w == b"\r\n") {
        let (line, tail) = rest.split_at(at);
        lines.push(line);
        rest = tail.get(2..).unwrap_or_default();
    }
    if !rest.is_empty() {
        return Err(HttpError::BadRequest(
            "the head does not end with an empty line",
        ));
    }
    if lines
        .iter()
        .any(|l| l.contains(&b'\r') || l.contains(&b'\n'))
    {
        return Err(HttpError::BadRequest("bare CR or LF in the head"));
    }
    let mut lines = lines.into_iter();
    let request_line = lines.next().ok_or(HttpError::BadRequest("empty request"))?;
    let (method, target) = parse_request_line(request_line)?;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut ended = false;
    for line in lines {
        if line.is_empty() {
            ended = true;
            break;
        }
        if headers.len() >= max_headers {
            return Err(HttpError::HeadersTooLarge);
        }
        let (name, value) = parse_header_line(line)?;
        if SINGLETONS.contains(&name.as_str()) && headers.iter().any(|(k, _)| *k == name) {
            return Err(HttpError::BadRequest("duplicate header"));
        }
        headers.push((name, value));
    }
    if !ended {
        return Err(HttpError::BadRequest(
            "the head does not end with an empty line",
        ));
    }
    Ok(Head {
        method,
        target,
        headers,
    })
}

/// How the body of a request is delimited and what to do with the connection afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Framing {
    pub content_length: usize,
    pub expect_continue: bool,
    pub keep_alive: bool,
}

pub fn framing(head: &Head, max_body: usize) -> Result<Framing, HttpError> {
    if head.header("host").is_none() {
        return Err(HttpError::BadRequest("Host is required"));
    }
    if head.header("transfer-encoding").is_some() {
        return Err(HttpError::NotImplemented(
            "Transfer-Encoding is not supported, send Content-Length",
        ));
    }
    let content_length = match head.header("content-length") {
        None => {
            if head.method == "POST" {
                return Err(HttpError::LengthRequired);
            }
            0
        }
        Some(text) => {
            if text.is_empty() || text.len() > 12 || !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err(HttpError::BadRequest("invalid Content-Length"));
            }
            let n: u64 = text
                .parse()
                .map_err(|_| HttpError::BadRequest("invalid Content-Length"))?;
            if n > max_body as u64 {
                return Err(HttpError::PayloadTooLarge);
            }
            n as usize
        }
    };
    let expect_continue = match head.header("expect") {
        None => false,
        Some(v) if v.eq_ignore_ascii_case("100-continue") => true,
        Some(_) => return Err(HttpError::ExpectationFailed),
    };
    let keep_alive = !head
        .joined("connection")
        .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")));
    Ok(Framing {
        content_length,
        expect_continue,
        keep_alive,
    })
}

fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        417 => "Expectation Failed",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Status",
    }
}

fn write_response(
    stream: &mut TcpStream,
    response: &Response,
    keep_alive: bool,
    head_only: bool,
) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n",
        response.status,
        reason(response.status)
    );
    if response.status != 202 || !response.body.is_empty() {
        head.push_str("Content-Type: application/json\r\n");
    }
    head.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
    head.push_str("Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n");
    head.push_str(if keep_alive {
        "Connection: keep-alive\r\n"
    } else {
        "Connection: close\r\n"
    });
    if let Some(secs) = response.retry_after_secs {
        head.push_str(&format!("Retry-After: {secs}\r\n"));
    }
    if let Some(allow) = response.allow {
        head.push_str(&format!("Allow: {allow}\r\n"));
    }
    if response.challenge {
        head.push_str("WWW-Authenticate: Bearer realm=\"mcp-remote-gate\"\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    if !head_only {
        out.extend_from_slice(&response.body);
    }
    stream.write_all(&out)?;
    stream.flush()
}

fn error_response(error: HttpError) -> Response {
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{{\"code\":-32600,\"message\":{}}}}}",
        gate_domain::json::quote(error.message())
    );
    Response {
        status: error.status(),
        body: body.into_bytes(),
        retry_after_secs: None,
        allow: None,
        challenge: false,
    }
}

pub type Handler = Arc<dyn Fn(&Request) -> Response + Send + Sync>;

/// Looks at a request before its body is read (the `body` it sees is empty). A refusal is sent at
/// once, without `100 Continue` and without reading what the client announced, and the connection
/// is closed. This is how a client that cannot authenticate is kept from holding a connection and
/// from making the server buffer a body.
pub type Preflight = Arc<dyn Fn(&Request) -> Option<Response> + Send + Sync>;

/// Limits how often something is logged: at most `per_minute` messages per minute.
struct LogThrottle {
    state: Mutex<(Instant, u32, u32)>,
    per_minute: u32,
}

impl LogThrottle {
    fn new(per_minute: u32) -> LogThrottle {
        LogThrottle {
            state: Mutex::new((Instant::now(), 0, 0)),
            per_minute,
        }
    }

    /// Returns the number of messages that were dropped before this one, or `None` to drop it.
    fn allow(&self) -> Option<u32> {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if st.0.elapsed() >= Duration::from_secs(60) {
            *st = (Instant::now(), 0, st.2);
        }
        if st.1 >= self.per_minute {
            st.2 += 1;
            return None;
        }
        st.1 += 1;
        Some(std::mem::take(&mut st.2))
    }
}

struct Shared {
    limits: HttpLimits,
    handler: Handler,
    preflight: Option<Preflight>,
    log: Arc<dyn Logger>,
    stop: AtomicBool,
    active: AtomicUsize,
    reject_log: LogThrottle,
}

pub struct HttpServer {
    addr: SocketAddr,
    shared: Arc<Shared>,
    accept: Option<JoinHandle<()>>,
}

struct ConnGuard(Arc<Shared>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl HttpServer {
    pub fn start(
        listener: TcpListener,
        limits: HttpLimits,
        handler: Handler,
        log: Arc<dyn Logger>,
    ) -> io::Result<HttpServer> {
        HttpServer::start_with_preflight(listener, limits, handler, None, log)
    }

    pub fn start_with_preflight(
        listener: TcpListener,
        limits: HttpLimits,
        handler: Handler,
        preflight: Option<Preflight>,
        log: Arc<dyn Logger>,
    ) -> io::Result<HttpServer> {
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let shared = Arc::new(Shared {
            limits,
            handler,
            preflight,
            log,
            stop: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            reject_log: LogThrottle::new(10),
        });
        let for_thread = Arc::clone(&shared);
        let accept = std::thread::Builder::new()
            .name("http-accept".into())
            .spawn(move || accept_loop(&listener, &for_thread))?;
        Ok(HttpServer {
            addr,
            shared,
            accept: Some(accept),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn active_connections(&self) -> usize {
        self.shared.active.load(Ordering::SeqCst)
    }

    /// Stops accepting, lets the requests in progress finish for up to `drain`, and returns the
    /// number of connections still open after that.
    pub fn stop(mut self, drain: Duration) -> usize {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
        let deadline = Instant::now() + drain;
        while self.shared.active.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        self.shared.active.load(Ordering::SeqCst)
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
    }
}

fn accept_loop(listener: &TcpListener, shared: &Arc<Shared>) {
    while !shared.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_nodelay(true);
                let _ = stream.set_write_timeout(Some(shared.limits.write_timeout));
                if shared.active.fetch_add(1, Ordering::SeqCst) >= shared.limits.max_connections {
                    shared.active.fetch_sub(1, Ordering::SeqCst);
                    let mut busy = error_response(HttpError::BadRequest("too many connections"));
                    busy.status = 503;
                    busy.retry_after_secs = Some(1);
                    let _ = write_response(&mut stream, &busy, false, false);
                    continue;
                }
                let guard = ConnGuard(Arc::clone(shared));
                let for_conn = Arc::clone(shared);
                let spawned =
                    std::thread::Builder::new()
                        .name("http-conn".into())
                        .spawn(move || {
                            let _guard = guard;
                            serve_connection(stream, peer, &for_conn);
                        });
                if spawned.is_err() {
                    // the guard moved into the closure that never ran and is dropped with it
                    shared
                        .log
                        .log(Level::Error, "cannot start a connection thread");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(15))
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                shared.log.log(Level::Warn, &format!("accept failed: {e}"));
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

enum Fill {
    Data,
    Eof,
    Timeout,
    Stopped,
}

/// Reads more bytes into `buf` before `deadline`, waking up every 200 ms to see whether the
/// server is stopping (only when `interruptible`).
fn fill(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    deadline: Instant,
    stop: &AtomicBool,
    interruptible: bool,
) -> io::Result<Fill> {
    let mut chunk = [0u8; 8192];
    loop {
        if interruptible && stop.load(Ordering::SeqCst) {
            return Ok(Fill::Stopped);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(Fill::Timeout);
        }
        let step = (deadline - now).min(Duration::from_millis(200));
        stream.set_read_timeout(Some(step.max(Duration::from_millis(1))))?;
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(Fill::Eof),
            Ok(n) => {
                buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
                return Ok(Fill::Data);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
}

fn find_head_end(buf: &[u8], from: usize) -> Option<usize> {
    let start = from.saturating_sub(3);
    buf.get(start..)?
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| start + p + 4)
}

fn method_of(name: &str) -> HttpMethod {
    match name {
        "POST" => HttpMethod::Post,
        "GET" => HttpMethod::Get,
        "DELETE" => HttpMethod::Delete,
        "OPTIONS" => HttpMethod::Options,
        _ => HttpMethod::Other,
    }
}

fn serve_connection(mut stream: TcpStream, peer: SocketAddr, shared: &Shared) {
    let limits = &shared.limits;
    let mut buf: Vec<u8> = Vec::new();
    for served in 0..limits.max_requests_per_connection {
        // wait for the first byte of the next request
        if buf.is_empty() {
            let idle = if served == 0 {
                limits.header_timeout
            } else {
                limits.idle_timeout
            };
            match fill(
                &mut stream,
                &mut buf,
                Instant::now() + idle,
                &shared.stop,
                true,
            ) {
                Ok(Fill::Data) => {}
                _ => return,
            }
        }
        let deadline = Instant::now() + limits.header_timeout;
        let reject = |stream: &mut TcpStream, error: HttpError| {
            if let Some(dropped) = shared.reject_log.allow() {
                let extra = if dropped > 0 {
                    format!(" ({dropped} similar messages dropped)")
                } else {
                    String::new()
                };
                shared.log.log(
                    Level::Warn,
                    &format!(
                        "refused a request from {}: {}{extra}",
                        peer.ip(),
                        escape_control(error.message(), 80)
                    ),
                );
            }
            let _ = write_response(stream, &error_response(error), false, false);
        };
        // the head
        let head_end = loop {
            if let Some(end) = find_head_end(&buf, 0) {
                if end > limits.max_head_bytes {
                    return reject(&mut stream, HttpError::HeadersTooLarge);
                }
                break end;
            }
            if buf.len() > limits.max_head_bytes {
                return reject(&mut stream, HttpError::HeadersTooLarge);
            }
            match fill(&mut stream, &mut buf, deadline, &shared.stop, false) {
                Ok(Fill::Data) => {}
                Ok(Fill::Timeout) => return reject(&mut stream, HttpError::Timeout),
                _ => return,
            }
        };
        let head = match buf
            .get(..head_end)
            .map(|b| parse_head(b, limits.max_headers))
        {
            Some(Ok(head)) => head,
            Some(Err(e)) => return reject(&mut stream, e),
            None => return,
        };
        let framing = match framing(&head, limits.max_body_bytes) {
            Ok(f) => f,
            Err(e) => return reject(&mut stream, e),
        };
        let path = head.target.split('?').next().unwrap_or("").to_string();
        let mut request = Request {
            method: method_of(&head.method),
            path,
            host: head.header("host").map(str::to_string),
            origin: head.header("origin").map(str::to_string),
            authorization: head.header("authorization").map(str::to_string),
            content_type: head.header("content-type").map(str::to_string),
            accept: head.joined("accept"),
            protocol_version: head.header("mcp-protocol-version").map(str::to_string),
            body: Vec::new(),
            peer: Some(peer.ip().to_string()),
        };
        // before the body: a client that is not welcome gets its answer now, not a go-ahead
        if let Some(preflight) = &shared.preflight {
            if let Some(refusal) = preflight(&request) {
                let _ = write_response(&mut stream, &refusal, false, head.method == "HEAD");
                return;
            }
        }
        // the body
        let total = head_end + framing.content_length;
        if framing.expect_continue
            && buf.len() < total
            && stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").is_err()
        {
            return;
        }
        while buf.len() < total {
            match fill(&mut stream, &mut buf, deadline, &shared.stop, false) {
                Ok(Fill::Data) => {}
                Ok(Fill::Timeout) => return reject(&mut stream, HttpError::Timeout),
                _ => return,
            }
        }
        request.body = buf.get(head_end..total).unwrap_or_default().to_vec();
        buf.drain(..total);
        let response = (shared.handler)(&request);
        let keep_alive = framing.keep_alive && !shared.stop.load(Ordering::SeqCst);
        if write_response(&mut stream, &response, keep_alive, head.method == "HEAD").is_err()
            || !keep_alive
        {
            return;
        }
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

    fn head(text: &str) -> Result<Head, HttpError> {
        parse_head(text.as_bytes(), 64)
    }

    const OK: &str = "POST /mcp HTTP/1.1\r\nHost: localhost:8787\r\nContent-Length: 2\r\n\r\n";

    #[test]
    fn a_normal_request_parses() {
        let h = head("POST /mcp?x=1 HTTP/1.1\r\nHost: localhost:8787\r\nAuthorization:   Bearer abc \r\nAccept: application/json\r\nAccept: text/event-stream\r\nContent-Length: 12\r\n\r\n").unwrap();
        assert_eq!((h.method.as_str(), h.target.as_str()), ("POST", "/mcp?x=1"));
        assert_eq!(h.header("host"), Some("localhost:8787"));
        assert_eq!(h.header("authorization"), Some("Bearer abc"));
        assert_eq!(
            h.joined("accept").as_deref(),
            Some("application/json, text/event-stream")
        );
        assert_eq!(h.header("missing"), None);
        let f = framing(&h, 100).unwrap();
        assert_eq!(
            (f.content_length, f.expect_continue, f.keep_alive),
            (12, false, true)
        );
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let h = head("GET / HTTP/1.1\r\nHOST: a\r\nX-Mixed-CASE: v\r\n\r\n").unwrap();
        assert_eq!(h.header("host"), Some("a"));
        assert_eq!(h.header("x-mixed-case"), Some("v"));
    }

    #[test]
    fn smuggling_shapes_are_refused() {
        let cases: [(&str, &str); 14] = [
            ("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n", "duplicate"),
            ("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\ncontent-length: 2\r\n\r\n", "duplicate"),
            ("POST / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", "duplicate"),
            ("POST / HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer x\r\nAuthorization: Bearer y\r\n\r\n", "duplicate"),
            ("POST / HTTP/1.1\r\nHost: a\r\nOrigin: http://a\r\nOrigin: http://b\r\n\r\n", "duplicate"),
            ("POST / HTTP/1.1\r\nHost : a\r\n\r\n", "header name"),
            ("POST / HTTP/1.1\r\nHost: a\r\n Content-Length: 5\r\n\r\n", "folding"),
            ("POST / HTTP/1.1\r\nHost: a\r\n\tx: y\r\n\r\n", "folding"),
            ("POST / HTTP/1.1\r\nHost: a\nContent-Length: 5\r\n\r\n", "bare"),
            ("POST / HTTP/1.1\r\nHost: a\rContent-Length: 5\r\n\r\n", "bare"),
            ("POST / HTTP/1.1\nHost: a\n\n", "end with an empty line"),
            ("POST / HTTP/1.1\r\nHost: a\r\nX: \u{0}\r\n\r\n", "control"),
            ("POST / HTTP/1.1\r\nHost: a\r\nno-colon\r\n\r\n", "malformed header"),
            ("POST / HTTP/1.1\r\nHost: a\r\n: v\r\n\r\n", "header name"),
        ];
        for (text, expect) in cases {
            match head(text) {
                Err(HttpError::BadRequest(m)) => assert!(m.contains(expect), "{text:?}: {m}"),
                other => panic!("{text:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn request_line_variants() {
        for text in [
            "POST  /mcp HTTP/1.1\r\nHost: a\r\n\r\n",
            "POST /mcp  HTTP/1.1\r\nHost: a\r\n\r\n",
            " POST /mcp HTTP/1.1\r\nHost: a\r\n\r\n",
            "POST /mcp HTTP/1.1 \r\nHost: a\r\n\r\n",
            "POST /mcp\r\nHost: a\r\n\r\n",
            "POST http://evil/mcp HTTP/1.1\r\nHost: a\r\n\r\n",
            "CONNECT a:80 HTTP/1.1\r\nHost: a\r\n\r\n",
            "POST * HTTP/1.1\r\nHost: a\r\n\r\n",
            "POST /a#frag HTTP/1.1\r\nHost: a\r\n\r\n",
            "POST /a\u{e9} HTTP/1.1\r\nHost: a\r\n\r\n",
            "PO\tST / HTTP/1.1\r\nHost: a\r\n\r\n",
            "POST / http/1.1\r\nHost: a\r\n\r\n",
            "\r\nPOST / HTTP/1.1\r\nHost: a\r\n\r\n",
            "POST / HTTP/1.1 junk\r\nHost: a\r\n\r\n",
        ] {
            assert!(
                matches!(head(text), Err(HttpError::BadRequest(_))),
                "{text:?}: {:?}",
                head(text)
            );
        }
        assert_eq!(
            head("POST / HTTP/1.0\r\nHost: a\r\n\r\n"),
            Err(HttpError::VersionNotSupported)
        );
        assert_eq!(
            head("POST / HTTP/2.0\r\nHost: a\r\n\r\n"),
            Err(HttpError::VersionNotSupported)
        );
        assert_eq!(
            head(&format!(
                "POST /{} HTTP/1.1\r\nHost: a\r\n\r\n",
                "a".repeat(3000)
            )),
            Err(HttpError::UriTooLong)
        );
    }

    #[test]
    fn header_limits() {
        let many: String = (0..70).map(|i| format!("X-{i}: v\r\n")).collect();
        assert_eq!(
            head(&format!("GET / HTTP/1.1\r\nHost: a\r\n{many}\r\n")),
            Err(HttpError::HeadersTooLarge)
        );
        assert!(parse_head(
            format!("GET / HTTP/1.1\r\nHost: a\r\n{many}\r\n").as_bytes(),
            100
        )
        .is_ok());
    }

    #[test]
    fn framing_rules() {
        let f = |text: &str| framing(&head(text).unwrap(), 1000);
        assert_eq!(
            f("POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\n"),
            Err(HttpError::BadRequest("Host is required"))
        );
        assert_eq!(
            f("POST / HTTP/1.1\r\nHost: a\r\n\r\n"),
            Err(HttpError::LengthRequired)
        );
        assert!(matches!(
            f("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(HttpError::NotImplemented(_))
        ));
        assert!(matches!(f("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n"), Err(HttpError::NotImplemented(_))));
        assert!(matches!(
            f("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: identity\r\n\r\n"),
            Err(HttpError::NotImplemented(_))
        ));
        for cl in [
            "-1",
            "+1",
            "1.0",
            "0x10",
            "1e3",
            "",
            " ",
            "1 2",
            "99999999999999999999",
            "٣",
        ] {
            assert!(
                matches!(
                    f(&format!(
                        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: {cl}\r\n\r\n"
                    )),
                    Err(HttpError::BadRequest(_))
                ),
                "{cl:?}"
            );
        }
        assert_eq!(
            f("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1001\r\n\r\n"),
            Err(HttpError::PayloadTooLarge)
        );
        assert_eq!(
            f("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1000\r\n\r\n")
                .unwrap()
                .content_length,
            1000
        );
        assert_eq!(
            f("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 007\r\n\r\n")
                .unwrap()
                .content_length,
            7
        );
        assert_eq!(
            f("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
                .unwrap()
                .content_length,
            0
        );
        assert!(
            f("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nExpect: 100-Continue\r\n\r\n")
                .unwrap()
                .expect_continue
        );
        assert_eq!(
            f("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nExpect: magic\r\n\r\n"),
            Err(HttpError::ExpectationFailed)
        );
        assert!(
            !f("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nConnection: Close\r\n\r\n")
                .unwrap()
                .keep_alive
        );
        assert!(!f("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nConnection: keep-alive, close\r\n\r\n").unwrap().keep_alive);
        assert!(f(OK).unwrap().keep_alive);
    }

    #[test]
    fn head_end_search_finds_split_terminators() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nbody", 0), Some(18));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r", 0), None);
        // a terminator that straddles the previously searched region
        let buf = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert_eq!(find_head_end(buf, buf.len() - 1), Some(buf.len()));
        assert_eq!(find_head_end(b"", 0), None);
    }

    #[test]
    fn error_statuses_and_messages() {
        for e in [
            HttpError::BadRequest("x"),
            HttpError::UriTooLong,
            HttpError::HeadersTooLarge,
            HttpError::NotImplemented("y"),
            HttpError::VersionNotSupported,
            HttpError::LengthRequired,
            HttpError::PayloadTooLarge,
            HttpError::ExpectationFailed,
            HttpError::Timeout,
        ] {
            assert!(e.status() >= 400 && !e.message().is_empty());
            assert_ne!(reason(e.status()), "Status");
            let body = String::from_utf8(error_response(e).body).unwrap();
            assert!(gate_domain::json::parse(&body).is_ok(), "{body}");
        }
    }

    #[test]
    fn random_garbage_never_panics() {
        let mut x = 0x1357_9bdf_2468_ace0u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let pieces = [
            "POST",
            " ",
            "/",
            "HTTP/1.1",
            "\r\n",
            "\r",
            "\n",
            "Host",
            ":",
            "a",
            "Content-Length",
            "5",
            "\t",
            "\u{0}",
            "é",
            "Transfer-Encoding",
        ];
        for _ in 0..4000 {
            let text: String = (0..next() % 40)
                .map(|_| pieces[(next() % pieces.len() as u64) as usize])
                .collect();
            if let Ok(h) = parse_head(text.as_bytes(), 64) {
                let _ = framing(&h, 100);
            }
        }
    }

    #[test]
    fn the_log_throttle_drops_the_excess_and_counts_it() {
        let t = LogThrottle::new(2);
        assert_eq!(t.allow(), Some(0));
        assert_eq!(t.allow(), Some(0));
        assert_eq!(t.allow(), None);
        assert_eq!(t.allow(), None);
        t.state.lock().unwrap().0 = Instant::now() - Duration::from_secs(61);
        assert_eq!(t.allow(), Some(2));
    }
}
