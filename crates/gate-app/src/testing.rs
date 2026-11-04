//! In-memory fakes of the ports, for the tests of this crate and of the adapters.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use gate_domain::audit::AuditRecord;
use gate_domain::framing::Line;
use gate_domain::json::{self, Value};
use gate_domain::jsonrpc::{self, Message, RpcError};
use gate_domain::mcp::ChildInfo;

use crate::ports::{
    AuditSink, ChildControl, ChildLink, ChildSpawner, Clock, ExitInfo, KillSwitch, Level, LineSink,
    LineSource, Logger, Read,
};
use crate::upstream::{UpstreamError, UpstreamPort};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A clock that moves only when told to; sleeping moves it by the slept time and returns at once.
#[derive(Debug, Default)]
pub struct FakeClock {
    mono: AtomicU64,
    unix_base: u64,
}

impl FakeClock {
    pub fn new() -> FakeClock {
        FakeClock {
            mono: AtomicU64::new(1_000),
            unix_base: 1_730_000_000_000,
        }
    }

    pub fn advance(&self, ms: u64) {
        self.mono.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn mono_ms(&self) -> u64 {
        self.mono.load(Ordering::SeqCst)
    }

    fn unix_ms(&self) -> u64 {
        self.unix_base + self.mono.load(Ordering::SeqCst)
    }

    fn sleep_ms(&self, ms: u64) {
        self.advance(ms);
    }
}

#[derive(Default)]
pub struct MemoryAudit {
    records: Mutex<Vec<AuditRecord>>,
    failing: AtomicBool,
}

impl MemoryAudit {
    pub fn new() -> MemoryAudit {
        MemoryAudit::default()
    }

    pub fn records(&self) -> Vec<AuditRecord> {
        lock(&self.records).clone()
    }

    /// Makes every further write fail, like a full disk.
    pub fn fail_writes(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }
}

impl AuditSink for MemoryAudit {
    fn record(&self, record: &AuditRecord) -> Result<(), String> {
        if self.failing.load(Ordering::SeqCst) {
            return Err("disk full".into());
        }
        lock(&self.records).push(record.clone());
        Ok(())
    }

    fn healthy(&self) -> bool {
        !self.failing.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
pub struct FlagKillSwitch(AtomicBool);

impl FlagKillSwitch {
    pub fn set(&self, on: bool) {
        self.0.store(on, Ordering::SeqCst);
    }
}

impl KillSwitch for FlagKillSwitch {
    fn engaged(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
pub struct VecLogger {
    lines: Mutex<Vec<(Level, String)>>,
}

impl VecLogger {
    pub fn lines(&self) -> Vec<(Level, String)> {
        lock(&self.lines).clone()
    }

    pub fn contains(&self, needle: &str) -> bool {
        lock(&self.lines).iter().any(|(_, m)| m.contains(needle))
    }
}

impl Logger for VecLogger {
    fn log(&self, level: Level, message: &str) {
        lock(&self.lines).push((level, message.to_string()));
    }
}

type UpstreamHandler =
    Box<dyn Fn(&str, Option<&Value>) -> Result<Value, UpstreamError> + Send + Sync>;
type BehaviorFactory = Box<dyn FnMut(usize) -> Result<Behavior, String> + Send>;

/// An upstream whose answers come from a closure.
pub struct FakeUpstream {
    handler: UpstreamHandler,
    info: Mutex<Result<ChildInfo, UpstreamError>>,
    calls: Mutex<Vec<(String, Option<Value>)>>,
}

impl FakeUpstream {
    pub fn new(
        handler: impl Fn(&str, Option<&Value>) -> Result<Value, UpstreamError> + Send + Sync + 'static,
    ) -> FakeUpstream {
        FakeUpstream {
            handler: Box::new(handler),
            info: Mutex::new(Ok(ChildInfo {
                protocol_version: "2025-06-18".into(),
                server_name: "fake".into(),
                server_version: "1".into(),
                has_tools: true,
            })),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// A server with the given tools: `tools/list` lists them, `tools/call` answers with text.
    pub fn with_tools(names: &[&str]) -> FakeUpstream {
        let names: Vec<String> = names.iter().map(|n| (*n).to_string()).collect();
        FakeUpstream::new(move |method, params| match method {
            "tools/list" => Ok(Value::object([(
                "tools",
                Value::Array(
                    names
                        .iter()
                        .map(|n| {
                            Value::object([
                                ("name", Value::str(n)),
                                ("description", Value::str("a tool")),
                                (
                                    "inputSchema",
                                    Value::object([("type", Value::str("object"))]),
                                ),
                            ])
                        })
                        .collect(),
                ),
            )])),
            "tools/call" => {
                let name = params
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("?");
                let args = params
                    .and_then(|p| p.get("arguments"))
                    .map_or_else(|| "null".to_string(), Value::to_json);
                Ok(Value::object([(
                    "content",
                    Value::Array(vec![Value::object([
                        ("type", Value::str("text")),
                        ("text", Value::String(format!("{name} ran with {args}"))),
                    ])]),
                )]))
            }
            other => Err(UpstreamError::Rpc(RpcError::new(
                jsonrpc::METHOD_NOT_FOUND,
                &format!("unknown method {other}"),
            ))),
        })
    }

    pub fn set_info(&self, info: Result<ChildInfo, UpstreamError>) {
        *lock(&self.info) = info;
    }

    /// The requests that reached the upstream, in order.
    pub fn calls(&self) -> Vec<(String, Option<Value>)> {
        lock(&self.calls).clone()
    }
}

impl UpstreamPort for FakeUpstream {
    fn info(&self) -> Result<ChildInfo, UpstreamError> {
        lock(&self.info).clone()
    }

    fn request(
        &self,
        method: &str,
        params: Option<Value>,
        _timeout_ms: u64,
    ) -> Result<Value, UpstreamError> {
        lock(&self.calls).push((method.to_string(), params.clone()));
        (self.handler)(method, params.as_ref())
    }
}

/// What a scripted child does in answer to a line.
pub enum ChildAction {
    /// Writes this text as a line.
    Say(String),
    /// Emits this event as it is (an oversized line, a premature end).
    Event(Read),
    /// The process ends.
    Exit { clean: bool },
}

pub type Behavior = Box<dyn FnMut(&Value) -> Vec<ChildAction> + Send>;

/// A fake upstream process: lines written to it are handed to a behavior closure on a thread of
/// its own, and what the closure returns is what the process "prints".
pub struct ScriptedSpawner {
    make: Mutex<BehaviorFactory>,
    spawns: AtomicUsize,
    received: Arc<Mutex<Vec<String>>>,
}

impl ScriptedSpawner {
    /// `make` is called for every start with the index of the start (0, 1, ...).
    pub fn new(
        make: impl FnMut(usize) -> Result<Behavior, String> + Send + 'static,
    ) -> Arc<ScriptedSpawner> {
        Arc::new(ScriptedSpawner {
            make: Mutex::new(Box::new(make)),
            spawns: AtomicUsize::new(0),
            received: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// The same behavior for every start.
    pub fn always(behavior: impl Fn() -> Behavior + Send + 'static) -> Arc<ScriptedSpawner> {
        ScriptedSpawner::new(move |_| Ok(behavior()))
    }

    pub fn spawn_count(&self) -> usize {
        self.spawns.load(Ordering::SeqCst)
    }

    /// Every line any child received, in order.
    pub fn received(&self) -> Vec<String> {
        lock(&self.received).clone()
    }
}

struct ScriptSink {
    to_child: Sender<Vec<u8>>,
}

impl LineSink for ScriptSink {
    fn send(&mut self, line: &[u8]) -> io::Result<()> {
        self.to_child
            .send(line.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "the fake child is gone"))
    }
}

struct ScriptSource {
    from_child: Receiver<Read>,
}

impl LineSource for ScriptSource {
    fn next(&mut self) -> Read {
        self.from_child.recv().unwrap_or(Read::Eof)
    }
}

/// How the fake process ended; `wait` blocks until it did, like waiting for a real process.
#[derive(Default)]
struct ExitCell {
    info: Mutex<Option<ExitInfo>>,
    ended: Condvar,
}

impl ExitCell {
    /// Records how the process ended unless it already did.
    fn set(&self, info: ExitInfo) {
        let mut slot = lock(&self.info);
        if slot.is_none() {
            *slot = Some(info);
        }
        drop(slot);
        self.ended.notify_all();
    }

    fn wait(&self) -> ExitInfo {
        let mut slot = lock(&self.info);
        loop {
            if let Some(info) = slot.clone() {
                return info;
            }
            slot = self
                .ended
                .wait(slot)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

struct ScriptControl {
    out: Mutex<Sender<Read>>,
    exit: Arc<ExitCell>,
}

impl ChildControl for ScriptControl {
    fn terminate(&self) {
        let _ = lock(&self.out).send(Read::Eof);
        self.exit.set(ExitInfo {
            clean: false,
            description: "terminated".into(),
        });
    }

    fn wait(&self) -> ExitInfo {
        self.exit.wait()
    }
}

impl ChildSpawner for ScriptedSpawner {
    fn spawn(&self) -> io::Result<ChildLink> {
        let index = self.spawns.fetch_add(1, Ordering::SeqCst);
        let mut behavior = (lock(&self.make))(index).map_err(io::Error::other)?;
        let (to_child, child_in) = channel::<Vec<u8>>();
        let (child_out, from_child) = channel::<Read>();
        let exit = Arc::new(ExitCell::default());
        let received = Arc::clone(&self.received);
        let thread_out = child_out.clone();
        let thread_exit = Arc::clone(&exit);
        std::thread::spawn(move || {
            while let Ok(bytes) = child_in.recv() {
                let text = String::from_utf8_lossy(&bytes).into_owned();
                lock(&received).push(text.clone());
                let Ok(value) = json::parse(&text) else {
                    continue;
                };
                for action in behavior(&value) {
                    match action {
                        ChildAction::Say(line) => {
                            let _ = thread_out.send(Read::Line(Line::Complete(line.into_bytes())));
                        }
                        ChildAction::Event(event) => {
                            let _ = thread_out.send(event);
                        }
                        ChildAction::Exit { clean } => {
                            thread_exit.set(ExitInfo {
                                clean,
                                description: if clean {
                                    "exit status 0".into()
                                } else {
                                    "exit status 1".into()
                                },
                            });
                            let _ = thread_out.send(Read::Eof);
                            return;
                        }
                    }
                }
            }
        });
        Ok(ChildLink {
            sink: Box::new(ScriptSink { to_child }),
            source: Box::new(ScriptSource { from_child }),
            control: Arc::new(ScriptControl {
                out: Mutex::new(child_out),
                exit,
            }),
        })
    }
}

/// A well-behaved MCP server: answers `initialize`, `ping`, `tools/list` and `tools/call` for
/// the given tool names. The tool `slow` never answers; `crash` makes the process exit.
pub fn mcp_behavior(tools: &[&str]) -> Behavior {
    let tools: Vec<String> = tools.iter().map(|t| (*t).to_string()).collect();
    Box::new(move |msg| {
        let Ok(Message::Request { id, method, params }) = jsonrpc::classify(msg.clone()) else {
            return vec![];
        };
        let say = |v: Value| vec![ChildAction::Say(v.to_json())];
        match method.as_str() {
            "initialize" => say(jsonrpc::response_ok(
                &id,
                Value::object([
                    ("protocolVersion", Value::str("2025-06-18")),
                    (
                        "capabilities",
                        Value::object([("tools", Value::Object(vec![]))]),
                    ),
                    (
                        "serverInfo",
                        Value::object([
                            ("name", Value::str("scripted")),
                            ("version", Value::str("1.0")),
                        ]),
                    ),
                ]),
            )),
            "ping" => say(jsonrpc::response_ok(&id, Value::Object(vec![]))),
            "tools/list" => say(jsonrpc::response_ok(
                &id,
                Value::object([(
                    "tools",
                    Value::Array(
                        tools
                            .iter()
                            .map(|t| Value::object([("name", Value::str(t))]))
                            .collect(),
                    ),
                )]),
            )),
            "tools/call" => {
                let name = params
                    .as_ref()
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                match name {
                    "slow" => vec![],
                    "crash" => vec![ChildAction::Exit { clean: false }],
                    n if tools.iter().any(|t| t == n) => {
                        let args = params
                            .as_ref()
                            .and_then(|p| p.get("arguments"))
                            .map_or_else(|| "null".to_string(), Value::to_json);
                        say(jsonrpc::response_ok(
                            &id,
                            Value::object([(
                                "content",
                                Value::Array(vec![Value::object([
                                    ("type", Value::str("text")),
                                    ("text", Value::String(format!("{n}:{args}"))),
                                ])]),
                            )]),
                        ))
                    }
                    _ => say(jsonrpc::response_error(
                        &id,
                        &RpcError::new(jsonrpc::INVALID_PARAMS, "unknown tool"),
                    )),
                }
            }
            _ => say(jsonrpc::response_error(
                &id,
                &RpcError::new(jsonrpc::METHOD_NOT_FOUND, "no such method"),
            )),
        }
    })
}
