//! The session with the upstream (child) MCP server.
//!
//! The gateway is the only JSON-RPC client the child ever sees. Every call that arrives over HTTP
//! is renumbered with an id of the gateway's own, so concurrent requests cannot collide, a
//! client cannot pick an id that clashes with another client's, and the answer of the child
//! finds its way back to exactly one waiting request. The session also owns the life of the
//! child: it performs the `initialize` handshake after every start, fails the calls in flight
//! when the child dies, and restarts it according to the restart policy.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use gate_domain::framing::Line;
use gate_domain::json::{self, Value};
use gate_domain::jsonrpc::{self, Message, RpcError};
use gate_domain::mcp::{handshake_params, ChildInfo};
use gate_domain::restart::{RestartDecision, RestartPolicy};
use gate_domain::sanitize::escape_control;

use crate::ports::{
    ChildControl, ChildLink, ChildSpawner, Clock, ExitInfo, Level, LineSource, Logger, Read,
};

/// How long a run must stay up before the failure counter of the restart policy starts over.
const HEALTHY_AFTER_MS: u64 = 60_000;
/// Calls that can wait for the writer thread of the child.
const WRITE_QUEUE: usize = 256;
const LOG_CHARS: usize = 160;

#[derive(Debug, Clone)]
pub struct UpstreamSettings {
    pub restart: RestartPolicy,
    pub startup_timeout_ms: u64,
    /// Calls that may wait for an answer at the same time.
    pub max_inflight: usize,
    pub gate_version: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UpstreamError {
    /// The child is not running or went away; the text says why.
    Unavailable(String),
    /// No answer within the timeout.
    Timeout,
    /// Too many calls are in flight.
    Busy,
    /// The answer line was longer than the configured maximum.
    TooLarge,
    /// The child answered with a JSON-RPC error.
    Rpc(RpcError),
}

/// What the gateway needs from the upstream session.
pub trait UpstreamPort: Send + Sync {
    /// What the child said about itself in its handshake.
    fn info(&self) -> Result<ChildInfo, UpstreamError>;
    /// Sends a request to the child and waits for its answer.
    fn request(
        &self,
        method: &str,
        params: Option<Value>,
        timeout_ms: u64,
    ) -> Result<Value, UpstreamError>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub invalid_lines: u64,
    pub oversized_lines: u64,
    pub ignored_notifications: u64,
    pub late_responses: u64,
    pub child_requests: u64,
    pub restarts: u64,
}

#[derive(Default)]
struct Stats {
    invalid_lines: AtomicU64,
    oversized_lines: AtomicU64,
    ignored_notifications: AtomicU64,
    late_responses: AtomicU64,
    child_requests: AtomicU64,
    restarts: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

#[derive(Debug, Clone, PartialEq)]
enum Phase {
    Starting,
    Handshaking,
    Ready,
    /// The child is gone and a restart is planned or being made.
    Down(String),
    /// The child is gone for good.
    Gone(String),
    Stopped,
}

type Reply = Result<Value, UpstreamError>;

struct State {
    phase: Phase,
    pending: HashMap<u64, SyncSender<Reply>>,
    next_id: u64,
    writer: Option<SyncSender<Vec<u8>>>,
    info: Option<ChildInfo>,
    control: Option<Arc<dyn ChildControl>>,
    /// Set once the first start ended, in a handshake or in a failure.
    first_outcome: bool,
}

struct Shared {
    settings: UpstreamSettings,
    spawner: Arc<dyn ChildSpawner>,
    clock: Arc<dyn Clock>,
    log: Arc<dyn Logger>,
    state: Mutex<State>,
    changed: Condvar,
    stop: AtomicBool,
    stats: Stats,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub struct StdioUpstream {
    shared: Arc<Shared>,
    supervisor: Mutex<Option<JoinHandle<()>>>,
}

impl StdioUpstream {
    /// Starts the child and waits for its handshake. Fails when the first start does not
    /// complete; later failures are handled by the restart policy.
    pub fn start(
        settings: UpstreamSettings,
        spawner: Arc<dyn ChildSpawner>,
        clock: Arc<dyn Clock>,
        log: Arc<dyn Logger>,
    ) -> Result<StdioUpstream, String> {
        let wait = Duration::from_millis(settings.startup_timeout_ms.saturating_add(2000));
        let shared = Arc::new(Shared {
            settings,
            spawner,
            clock,
            log,
            state: Mutex::new(State {
                phase: Phase::Starting,
                pending: HashMap::new(),
                next_id: 1,
                writer: None,
                info: None,
                control: None,
                first_outcome: false,
            }),
            changed: Condvar::new(),
            stop: AtomicBool::new(false),
            stats: Stats::default(),
        });
        let for_thread = Arc::clone(&shared);
        let handle = std::thread::Builder::new()
            .name("upstream-supervisor".into())
            .spawn(move || supervise(&for_thread))
            .map_err(|e| format!("cannot start the supervisor thread: {e}"))?;
        let upstream = StdioUpstream {
            shared,
            supervisor: Mutex::new(Some(handle)),
        };
        let mut st = lock(&upstream.shared.state);
        let step = Duration::from_millis(50);
        let mut waited = Duration::ZERO;
        loop {
            match &st.phase {
                Phase::Ready => break,
                Phase::Down(reason) | Phase::Gone(reason) if st.first_outcome => {
                    let reason = reason.clone();
                    drop(st);
                    upstream.shutdown();
                    return Err(reason);
                }
                _ => {}
            }
            if waited >= wait {
                drop(st);
                upstream.shutdown();
                return Err("the server did not finish its handshake in time".into());
            }
            let (guard, result) = upstream
                .shared
                .changed
                .wait_timeout(st, step)
                .unwrap_or_else(PoisonError::into_inner);
            st = guard;
            if result.timed_out() {
                waited += step;
            }
        }
        drop(st);
        Ok(upstream)
    }

    pub fn stats(&self) -> StatsSnapshot {
        let s = &self.shared.stats;
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        StatsSnapshot {
            invalid_lines: get(&s.invalid_lines),
            oversized_lines: get(&s.oversized_lines),
            ignored_notifications: get(&s.ignored_notifications),
            late_responses: get(&s.late_responses),
            child_requests: get(&s.child_requests),
            restarts: get(&s.restarts),
        }
    }

    /// A short description of the state, for logs and tests.
    pub fn status(&self) -> String {
        format!("{:?}", lock(&self.shared.state).phase)
    }

    /// Stops the child (and its process group) and the supervisor. Calls in flight fail.
    pub fn shutdown(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        let control = {
            let mut st = lock(&self.shared.state);
            st.phase = Phase::Stopped;
            st.control.clone()
        };
        self.shared.changed.notify_all();
        if let Some(control) = control {
            control.terminate();
        }
        fail_all_pending(&self.shared, "the gateway is shutting down");
        if let Some(handle) = lock(&self.supervisor).take() {
            let _ = handle.join();
        }
    }
}

impl Drop for StdioUpstream {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl UpstreamPort for StdioUpstream {
    fn info(&self) -> Result<ChildInfo, UpstreamError> {
        let st = lock(&self.shared.state);
        match (&st.phase, &st.info) {
            (Phase::Ready, Some(info)) => Ok(info.clone()),
            (Phase::Down(reason) | Phase::Gone(reason), _) => {
                Err(UpstreamError::Unavailable(reason.clone()))
            }
            _ => Err(UpstreamError::Unavailable("the server is not ready".into())),
        }
    }

    fn request(
        &self,
        method: &str,
        params: Option<Value>,
        timeout_ms: u64,
    ) -> Result<Value, UpstreamError> {
        call(&self.shared, method, params, timeout_ms, true)
    }
}

fn log(shared: &Shared, level: Level, message: &str) {
    shared.log.log(level, message);
}

fn fail_all_pending(shared: &Shared, reason: &str) {
    let drained: Vec<SyncSender<Reply>> = lock(&shared.state)
        .pending
        .drain()
        .map(|(_, tx)| tx)
        .collect();
    for tx in drained {
        let _ = tx.try_send(Err(UpstreamError::Unavailable(reason.to_string())));
    }
}

fn call(
    shared: &Shared,
    method: &str,
    params: Option<Value>,
    timeout_ms: u64,
    require_ready: bool,
) -> Reply {
    let (tx, rx) = sync_channel::<Reply>(1);
    let (id, queue) = {
        let mut st = lock(&shared.state);
        match &st.phase {
            Phase::Ready => {}
            Phase::Handshaking if !require_ready => {}
            Phase::Down(reason) | Phase::Gone(reason) => {
                return Err(UpstreamError::Unavailable(reason.clone()))
            }
            Phase::Stopped => {
                return Err(UpstreamError::Unavailable(
                    "the gateway is shutting down".into(),
                ))
            }
            Phase::Starting | Phase::Handshaking => {
                return Err(UpstreamError::Unavailable("the server is starting".into()))
            }
        }
        if require_ready && st.pending.len() >= shared.settings.max_inflight {
            return Err(UpstreamError::Busy);
        }
        let Some(queue) = st.writer.clone() else {
            return Err(UpstreamError::Unavailable(
                "the server is not running".into(),
            ));
        };
        let id = st.next_id;
        st.next_id += 1;
        st.pending.insert(id, tx);
        (id, queue)
    };
    let line = jsonrpc::request(&Value::uint(id), method, params)
        .to_json()
        .into_bytes();
    if let Err(e) = queue.try_send(line) {
        lock(&shared.state).pending.remove(&id);
        return Err(match e {
            TrySendError::Full(_) => UpstreamError::Busy,
            TrySendError::Disconnected(_) => {
                UpstreamError::Unavailable("the server is not running".into())
            }
        });
    }
    match rx.recv_timeout(Duration::from_millis(timeout_ms)) {
        Ok(reply) => reply,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let still_pending = lock(&shared.state).pending.remove(&id).is_some();
            if !still_pending {
                // the answer arrived between the timeout and here
                if let Ok(reply) = rx.try_recv() {
                    return reply;
                }
            }
            let cancel = jsonrpc::notification(
                "notifications/cancelled",
                Some(Value::object([
                    ("requestId", Value::uint(id)),
                    ("reason", Value::str("gateway timeout")),
                ])),
            );
            let _ = queue.try_send(cancel.to_json().into_bytes());
            Err(UpstreamError::Timeout)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(UpstreamError::Unavailable("the server went away".into()))
        }
    }
}

fn set_phase(shared: &Shared, phase: Phase) {
    let mut st = lock(&shared.state);
    // a shutdown wins over whatever the supervisor was about to record
    if st.phase != Phase::Stopped {
        if matches!(phase, Phase::Ready | Phase::Down(_) | Phase::Gone(_)) {
            st.first_outcome = true;
        }
        st.phase = phase;
    }
    drop(st);
    shared.changed.notify_all();
}

fn stopping(shared: &Shared) -> bool {
    shared.stop.load(Ordering::SeqCst)
}

fn supervise(shared: &Arc<Shared>) {
    let mut failures: u32 = 0;
    while !stopping(shared) {
        set_phase(shared, Phase::Starting);
        let started = shared.clock.mono_ms();
        let exit = match shared.spawner.spawn() {
            Ok(link) => run_generation(shared, link),
            Err(e) => {
                let text = escape_control(&e.to_string(), LOG_CHARS);
                log(
                    shared,
                    Level::Error,
                    &format!("cannot start the upstream server: {text}"),
                );
                ExitInfo {
                    clean: false,
                    description: format!("the server could not be started: {text}"),
                }
            }
        };
        if stopping(shared) {
            break;
        }
        if shared.clock.mono_ms().saturating_sub(started) >= HEALTHY_AFTER_MS {
            failures = 0;
        }
        match shared.settings.restart.decide(exit.clean, failures) {
            RestartDecision::Restart { delay_ms } => {
                log(
                    shared,
                    Level::Warn,
                    &format!(
                        "the upstream server ended ({}); restarting in {delay_ms} ms",
                        exit.description
                    ),
                );
                set_phase(
                    shared,
                    Phase::Down(format!(
                        "the server ended ({}) and is being restarted",
                        exit.description
                    )),
                );
                failures += 1;
                bump(&shared.stats.restarts);
                let mut left = delay_ms;
                while left > 0 && !stopping(shared) {
                    let step = left.min(100);
                    shared.clock.sleep_ms(step);
                    left -= step;
                }
            }
            RestartDecision::GiveUp(why) => {
                log(
                    shared,
                    Level::Error,
                    &format!(
                        "the upstream server ended ({}); not restarting: {why}",
                        exit.description
                    ),
                );
                set_phase(
                    shared,
                    Phase::Gone(format!(
                        "the server ended ({}) and will not be restarted: {why}",
                        exit.description
                    )),
                );
                break;
            }
        }
    }
}

fn run_generation(shared: &Arc<Shared>, link: ChildLink) -> ExitInfo {
    let ChildLink {
        mut sink,
        source,
        control,
    } = link;
    let (wtx, wrx) = sync_channel::<Vec<u8>>(WRITE_QUEUE);
    // The writer thread is detached on purpose: it ends when the pipe breaks or every sender is gone.
    let _ = std::thread::Builder::new()
        .name("upstream-writer".into())
        .spawn(move || {
            for line in wrx {
                if sink.send(&line).is_err() {
                    break;
                }
            }
        });
    {
        let mut st = lock(&shared.state);
        st.control = Some(Arc::clone(&control));
        st.writer = Some(wtx.clone());
        if st.phase != Phase::Stopped {
            st.phase = Phase::Handshaking;
        }
    }
    shared.changed.notify_all();
    if stopping(shared) {
        control.terminate();
    }
    // Watches the leader: when it exits, the control kills what is left of its group, which releases
    // the pipes a descendant may be holding, so the reader below always reaches the end of its stream.
    let watcher = {
        let control = Arc::clone(&control);
        std::thread::Builder::new()
            .name("upstream-watcher".into())
            .spawn(move || control.wait())
    };
    let reader = {
        let shared = Arc::clone(shared);
        let wtx = wtx.clone();
        std::thread::Builder::new()
            .name("upstream-reader".into())
            .spawn(move || read_loop(&shared, source, &wtx))
    };
    let handshake = call(
        shared,
        "initialize",
        Some(handshake_params(&shared.settings.gate_version)),
        shared.settings.startup_timeout_ms,
        false,
    )
    .map_err(|e| match e {
        UpstreamError::Timeout => "no answer to initialize".to_string(),
        UpstreamError::Rpc(e) => format!(
            "initialize failed: {}",
            escape_control(&e.message, LOG_CHARS)
        ),
        other => format!("initialize failed: {other:?}"),
    })
    .and_then(|result| ChildInfo::from_initialize(&result).map_err(str::to_string));
    match handshake {
        Ok(info) => {
            let _ = wtx.try_send(
                jsonrpc::notification("notifications/initialized", None)
                    .to_json()
                    .into_bytes(),
            );
            log(
                shared,
                Level::Info,
                &format!(
                    "upstream server ready: {} {} (protocol {})",
                    escape_control(&info.server_name, 64),
                    escape_control(&info.server_version, 32),
                    info.protocol_version
                ),
            );
            lock(&shared.state).info = Some(info);
            set_phase(shared, Phase::Ready);
        }
        Err(why) => {
            log(
                shared,
                Level::Error,
                &format!("upstream handshake failed: {why}"),
            );
            control.terminate();
        }
    }
    if let Ok(reader) = reader {
        let _ = reader.join();
    }
    control.terminate();
    let exit = control.wait();
    if let Ok(watcher) = watcher {
        let _ = watcher.join();
    }
    {
        let mut st = lock(&shared.state);
        st.writer = None;
        st.info = None;
        st.control = None;
    }
    fail_all_pending(shared, &format!("the server ended ({})", exit.description));
    exit
}

fn read_loop(shared: &Shared, mut source: Box<dyn LineSource>, writer: &SyncSender<Vec<u8>>) {
    loop {
        match source.next() {
            Read::Eof => return,
            Read::Line(Line::Complete(bytes)) => handle_line(shared, &bytes, writer),
            Read::Line(Line::Oversize { head, len }) => {
                bump(&shared.stats.oversized_lines);
                log(
                    shared,
                    Level::Warn,
                    &format!(
                        "dropped a {len} byte line from the upstream server (over the line limit)"
                    ),
                );
                if let Some(id) = leading_id(&head) {
                    resolve(shared, id, Err(UpstreamError::TooLarge));
                }
            }
        }
    }
}

fn resolve(shared: &Shared, id: u64, reply: Reply) {
    let waiter = lock(&shared.state).pending.remove(&id);
    match waiter {
        Some(tx) => {
            let _ = tx.try_send(reply);
        }
        None => bump(&shared.stats.late_responses),
    }
}

fn handle_line(shared: &Shared, bytes: &[u8], writer: &SyncSender<Vec<u8>>) {
    let parsed = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| json::parse(text).ok())
        .map(jsonrpc::classify);
    match parsed {
        Some(Ok(Message::Response { id, outcome })) => {
            let id = match &id {
                Value::Number(n) => n.parse::<u64>().ok(),
                _ => None,
            };
            match id {
                Some(id) => resolve(shared, id, outcome.map_err(UpstreamError::Rpc)),
                None => bump(&shared.stats.late_responses),
            }
        }
        Some(Ok(Message::Request { id, method, .. })) => {
            // the child asks the client for something (sampling, roots, ...): there is no client
            // behind the gateway to answer, except for ping
            bump(&shared.stats.child_requests);
            let answer = if method == "ping" {
                jsonrpc::response_ok(&id, Value::Object(vec![]))
            } else {
                jsonrpc::response_error(
                    &id,
                    &RpcError::new(
                        jsonrpc::METHOD_NOT_FOUND,
                        "the gateway does not serve requests from the server",
                    ),
                )
            };
            let _ = writer.try_send(answer.to_json().into_bytes());
        }
        Some(Ok(Message::Notification { .. })) => bump(&shared.stats.ignored_notifications),
        Some(Err(_)) | None => {
            bump(&shared.stats.invalid_lines);
            let text = escape_control(&String::from_utf8_lossy(bytes), LOG_CHARS);
            log(
                shared,
                Level::Warn,
                &format!("ignored a line that is not a JSON-RPC message: {text}"),
            );
        }
    }
}

/// The numeric `"id"` of a line that was too long to parse, read only from the top-level members
/// that come before any nested value: `{"jsonrpc":"2.0","id":7,...`. An `"id"` deeper in the
/// line (structured content, a string) is not the id of the message, so it is never looked at.
/// Used only to fail the matching call early instead of letting it time out; `None` means the
/// line is dropped and the timeout applies.
fn leading_id(head: &[u8]) -> Option<u64> {
    let mut at = 0usize;
    let blank = |at: &mut usize| {
        while matches!(head.get(*at), Some(b' ' | b'\t')) {
            *at += 1;
        }
    };
    let expect = |at: &mut usize, byte: u8| -> Option<()> {
        if head.get(*at) == Some(&byte) {
            *at += 1;
            Some(())
        } else {
            None
        }
    };
    // a string without escapes (keys) or with them (simple values); returns its content range
    let string = |at: &mut usize| -> Option<(usize, usize)> {
        if head.get(*at) != Some(&b'"') {
            return None;
        }
        *at += 1;
        let start = *at;
        loop {
            match head.get(*at)? {
                b'"' => {
                    *at += 1;
                    return Some((start, *at - 1));
                }
                b'\\' => *at += 2,
                _ => *at += 1,
            }
        }
    };
    blank(&mut at);
    expect(&mut at, b'{')?;
    loop {
        blank(&mut at);
        let (k0, k1) = string(&mut at)?;
        blank(&mut at);
        expect(&mut at, b':')?;
        blank(&mut at);
        if head.get(k0..k1)? == b"id" {
            let start = at;
            while matches!(head.get(at), Some(b'0'..=b'9')) {
                at += 1;
            }
            // the number must end inside the head, and end as an integer
            if at == start || !matches!(head.get(at)?, b',' | b'}' | b' ' | b'\t') {
                return None;
            }
            return std::str::from_utf8(head.get(start..at)?).ok()?.parse().ok();
        }
        match head.get(at)? {
            b'"' => {
                string(&mut at)?;
            }
            b'{' | b'[' => return None,
            _ => {
                while !matches!(head.get(at)?, b',' | b'}' | b' ' | b'\t') {
                    at += 1;
                }
            }
        }
        blank(&mut at);
        expect(&mut at, b',')?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_id_cases() {
        assert_eq!(
            leading_id(br#"{"jsonrpc":"2.0","id":42,"result":{"#),
            Some(42)
        );
        assert_eq!(leading_id(br#"{ "id" : 7 , "jsonrpc":"2.0"#), Some(7));
        assert_eq!(leading_id(br#"{"id":7}"#), Some(7));
        assert_eq!(
            leading_id(br#"{"jsonrpc":"2.0","id":"abc","result":{"#),
            None
        );
        assert_eq!(leading_id(br#"{"jsonrpc":"2.0","result":{"#), None);
        assert_eq!(leading_id(br#"{"id":99999999999999999999999"#), None);
        assert_eq!(
            leading_id(br#"{"id":4"#),
            None,
            "a number that may continue is not an id"
        );
        assert_eq!(leading_id(br#"{"id":4.5,"#), None);
        assert_eq!(leading_id(br#"{"id":-4,"#), None);
        assert_eq!(leading_id(b""), None);
    }

    #[test]
    fn an_id_inside_a_nested_value_is_not_the_id_of_the_message() {
        // the result comes first, and a structured payload has an "id" of its own
        for head in [
            br#"{"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"x"}],"structuredContent":{"id":3,"n":1"#.as_slice(),
            br#"{"result":{"id":3,"#.as_slice(),
            br#"{"jsonrpc":"2.0","params":[{"id":3}],"id":4,"#.as_slice(),
            br#"{"jsonrpc":"2.0","result":"a \"id\":3 inside a string","#.as_slice(),
            br#"{"jsonrpc":"2.0","result":"{\"id\":3}","#.as_slice(),
            br#"[{"id":3}"#.as_slice(),
        ] {
            assert_eq!(leading_id(head), None, "{}", String::from_utf8_lossy(head));
        }
    }
}
