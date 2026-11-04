//! The interfaces the use cases need from the outside world. The adapters implement them with
//! real processes, files and clocks; the tests implement them in memory.

use std::io;
use std::sync::Arc;

use gate_domain::audit::AuditRecord;
use gate_domain::framing::Line;

/// Time. `mono_ms` never goes backwards and is used for durations and rate limits; `unix_ms`
/// stamps the audit log.
pub trait Clock: Send + Sync {
    fn mono_ms(&self) -> u64;
    fn unix_ms(&self) -> u64;
    fn sleep_ms(&self, ms: u64);
}

pub trait AuditSink: Send + Sync {
    /// Appends one record. A sink that cannot write reports it here and through
    /// [`AuditSink::healthy`].
    fn record(&self, record: &AuditRecord) -> Result<(), String>;
    /// False once a write failed; the gateway then refuses tool calls instead of running them
    /// without a trail.
    fn healthy(&self) -> bool;
}

/// A switch that makes the gateway answer 503 at once.
pub trait KillSwitch: Send + Sync {
    fn engaged(&self) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

/// Diagnostics for the operator. The use cases pass only text they have already escaped.
pub trait Logger: Send + Sync {
    fn log(&self, level: Level, message: &str);
}

/// What the reader of the upstream server's stdout produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    Line(Line),
    /// The stream ended: the process closed its output or died.
    Eof,
}

pub trait LineSource: Send {
    /// Blocks until the next line or the end of the stream.
    fn next(&mut self) -> Read;
}

pub trait LineSink: Send {
    /// Writes one line (the adapter appends the newline).
    fn send(&mut self, line: &[u8]) -> io::Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitInfo {
    /// The process exited with status 0.
    pub clean: bool,
    pub description: String,
}

pub trait ChildControl: Send + Sync {
    /// Stops the process and everything it started: a polite signal first, a kill after the
    /// grace period. Safe to call on a process that is already gone and more than once.
    fn terminate(&self);
    /// Waits for the process to be gone and reports how it ended.
    fn wait(&self) -> ExitInfo;
}

/// One running upstream server.
pub struct ChildLink {
    pub sink: Box<dyn LineSink>,
    pub source: Box<dyn LineSource>,
    pub control: Arc<dyn ChildControl>,
}

pub trait ChildSpawner: Send + Sync {
    fn spawn(&self) -> io::Result<ChildLink>;
}
