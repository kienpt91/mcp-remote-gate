//! The upstream server as a real child process: fixed argv, a minimal environment, its own
//! process group, resource limits, and a pipe pair that carries newline-delimited JSON.

use std::collections::BTreeMap;
use std::io::{self, Read as _, Write as _};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use gate_app::ports::{
    ChildControl, ChildLink, ChildSpawner, ExitInfo, Level, LineSink, LineSource, Logger, Read,
};
use gate_domain::config::ChildConfig;
use gate_domain::framing::{Line, LineSplitter};
use gate_domain::sanitize::escape_control;
use gate_sys::{prepare_child, signal_group, Limits, Signal};

/// Longest line of the child's standard error that is logged.
const STDERR_LINE_MAX: usize = 512;
/// Lines of standard error logged per second; the rest are counted.
const STDERR_LINES_PER_SECOND: u32 = 50;

pub struct ProcessSpawner {
    config: ChildConfig,
    log: Arc<dyn Logger>,
}

impl ProcessSpawner {
    pub fn new(config: ChildConfig, log: Arc<dyn Logger>) -> ProcessSpawner {
        ProcessSpawner { config, log }
    }

    /// The environment of the child: the inherited names that are set, then the configured
    /// values (which win). Nothing else.
    pub fn environment(
        config: &ChildConfig,
        parent: &dyn Fn(&str) -> Option<String>,
    ) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        for name in &config.inherit_env {
            if let Some(value) = parent(name) {
                env.insert(name.clone(), value);
            }
        }
        for (name, value) in &config.env {
            env.insert(name.clone(), value.clone());
        }
        env
    }

    fn command(&self) -> io::Result<Command> {
        let (program, args) = self
            .config
            .command
            .split_first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty command"))?;
        let mut cmd = Command::new(program);
        cmd.args(args).env_clear();
        for (name, value) in Self::environment(&self.config, &|n| std::env::var(n).ok()) {
            cmd.env(name, value);
        }
        if let Some(cwd) = &self.config.cwd {
            cmd.current_dir(cwd);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        prepare_child(
            &mut cmd,
            Limits {
                memory_mb: self.config.limits.memory_mb,
                cpu_seconds: self.config.limits.cpu_seconds,
                max_open_files: self.config.limits.max_open_files,
                max_file_mb: self.config.limits.max_file_mb,
            },
        );
        Ok(cmd)
    }
}

impl ChildSpawner for ProcessSpawner {
    fn spawn(&self) -> io::Result<ChildLink> {
        let mut child = self.command()?.spawn()?;
        let pgid = child.id();
        let (Some(stdin), Some(stdout), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("the child has no standard streams"));
        };
        let log = Arc::clone(&self.log);
        std::thread::Builder::new()
            .name("upstream-stderr".into())
            .spawn(move || drain_stderr(stderr, log.as_ref()))?;
        Ok(ChildLink {
            sink: Box::new(PipeSink { stdin }),
            source: Box::new(PipeSource::new(stdout, self.config.max_line_bytes)),
            control: Arc::new(ProcessControl {
                state: Mutex::new(ProcState {
                    child: Some(child),
                    exit: None,
                }),
                pgid,
                grace: Duration::from_millis(self.config.shutdown_grace_ms),
            }),
        })
    }
}

struct PipeSink {
    stdin: ChildStdin,
}

impl LineSink for PipeSink {
    fn send(&mut self, line: &[u8]) -> io::Result<()> {
        let mut framed = Vec::with_capacity(line.len() + 1);
        framed.extend_from_slice(line);
        framed.push(b'\n');
        self.stdin.write_all(&framed)?;
        self.stdin.flush()
    }
}

struct PipeSource {
    stdout: ChildStdout,
    splitter: LineSplitter,
    ready: std::collections::VecDeque<Line>,
    buf: Vec<u8>,
}

impl PipeSource {
    fn new(stdout: ChildStdout, max_line: usize) -> PipeSource {
        PipeSource {
            stdout,
            splitter: LineSplitter::new(max_line),
            ready: std::collections::VecDeque::new(),
            buf: vec![0; 64 * 1024],
        }
    }
}

impl LineSource for PipeSource {
    fn next(&mut self) -> Read {
        loop {
            if let Some(line) = self.ready.pop_front() {
                return Read::Line(line);
            }
            match self.stdout.read(&mut self.buf) {
                Ok(0) => return Read::Eof,
                Ok(n) => {
                    let mut lines = Vec::new();
                    self.splitter
                        .push(self.buf.get(..n).unwrap_or_default(), &mut lines);
                    self.ready.extend(lines);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Read::Eof,
            }
        }
    }
}

fn drain_stderr(mut stderr: ChildStderr, log: &dyn Logger) {
    let mut splitter = LineSplitter::new(STDERR_LINE_MAX);
    let mut buf = vec![0u8; 8192];
    let mut window_start = Instant::now();
    let (mut logged, mut dropped) = (0u32, 0u32);
    loop {
        let n = match stderr.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let mut lines = Vec::new();
        splitter.push(buf.get(..n).unwrap_or_default(), &mut lines);
        for line in lines {
            if window_start.elapsed() >= Duration::from_secs(1) {
                if dropped > 0 {
                    log.log(
                        Level::Warn,
                        &format!("upstream stderr: {dropped} more lines were dropped"),
                    );
                }
                (window_start, logged, dropped) = (Instant::now(), 0, 0);
            }
            if logged >= STDERR_LINES_PER_SECOND {
                dropped += 1;
                continue;
            }
            logged += 1;
            let text = match &line {
                Line::Complete(bytes) => String::from_utf8_lossy(bytes).into_owned(),
                Line::Oversize { head, .. } => format!("{}[...]", String::from_utf8_lossy(head)),
            };
            log.log(
                Level::Info,
                &format!(
                    "upstream stderr: {}",
                    escape_control(&text, STDERR_LINE_MAX)
                ),
            );
        }
    }
}

struct ProcState {
    child: Option<Child>,
    exit: Option<ExitInfo>,
}

struct ProcessControl {
    state: Mutex<ProcState>,
    pgid: u32,
    grace: Duration,
}

fn describe(status: ExitStatus) -> ExitInfo {
    let description = match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit status {code}"),
        (None, Some(signal)) => format!("killed by signal {signal}"),
        _ => "ended".to_string(),
    };
    ExitInfo {
        clean: status.success(),
        description,
    }
}

fn lock(m: &Mutex<ProcState>) -> MutexGuard<'_, ProcState> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ProcessControl {
    /// Reaps the leader if it is gone and remembers how it ended.
    fn poll_exit(&self) -> bool {
        let mut st = lock(&self.state);
        if st.exit.is_some() {
            return true;
        }
        let status = match st.child.as_mut().map(Child::try_wait) {
            Some(Ok(Some(status))) => Some(status),
            Some(Err(_)) => Some(ExitStatus::from_raw(0)),
            _ => None,
        };
        match status {
            Some(status) => {
                st.exit = Some(describe(status));
                st.child = None;
                true
            }
            None => st.child.is_none(),
        }
    }
}

impl ChildControl for ProcessControl {
    fn terminate(&self) {
        if self.poll_exit() {
            // the leader is gone; stragglers of its group get the same treatment
            let _ = signal_group(self.pgid, Signal::Kill);
            return;
        }
        let _ = signal_group(self.pgid, Signal::Term);
        let deadline = Instant::now() + self.grace;
        while Instant::now() < deadline {
            if self.poll_exit() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // whatever survived the polite signal, and anything the leader left behind, is killed
        let _ = signal_group(self.pgid, Signal::Kill);
    }

    fn wait(&self) -> ExitInfo {
        loop {
            if self.poll_exit() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        lock(&self.state).exit.clone().unwrap_or(ExitInfo {
            clean: false,
            description: "ended".into(),
        })
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
    use gate_app::testing::VecLogger;
    use gate_domain::config::ChildLimits;
    use gate_domain::restart::{RestartMode, RestartPolicy};

    fn config(command: &[&str]) -> ChildConfig {
        ChildConfig {
            command: command.iter().map(|s| (*s).to_string()).collect(),
            cwd: None,
            env: vec![],
            inherit_env: vec!["PATH".into()],
            restart: RestartPolicy {
                mode: RestartMode::Never,
                max_restarts: 0,
                backoff_ms: 10,
                max_backoff_ms: 10,
            },
            max_line_bytes: 1024,
            startup_timeout_ms: 1000,
            shutdown_grace_ms: 300,
            limits: ChildLimits::default(),
        }
    }

    fn spawn(command: &[&str]) -> (ChildLink, Arc<VecLogger>) {
        let log = Arc::new(VecLogger::default());
        (
            ProcessSpawner::new(config(command), log.clone())
                .spawn()
                .unwrap(),
            log,
        )
    }

    #[test]
    fn lines_go_in_and_come_out() {
        let (mut link, _) = spawn(&["cat"]);
        link.sink.send(b"{\"a\":1}").unwrap();
        link.sink.send(b"{\"b\":2}").unwrap();
        assert_eq!(
            link.source.next(),
            Read::Line(Line::Complete(b"{\"a\":1}".to_vec()))
        );
        assert_eq!(
            link.source.next(),
            Read::Line(Line::Complete(b"{\"b\":2}".to_vec()))
        );
        link.control.terminate();
        assert_eq!(link.source.next(), Read::Eof);
        let exit = link.control.wait();
        assert!(
            !exit.clean && exit.description.contains("signal"),
            "{exit:?}"
        );
    }

    #[test]
    fn a_clean_exit_is_reported() {
        let (mut link, _) = spawn(&["sh", "-c", "echo hello; exit 0"]);
        assert_eq!(
            link.source.next(),
            Read::Line(Line::Complete(b"hello".to_vec()))
        );
        assert_eq!(link.source.next(), Read::Eof);
        let exit = link.control.wait();
        assert_eq!(
            (exit.clean, exit.description.as_str()),
            (true, "exit status 0")
        );
    }

    #[test]
    fn a_failing_exit_is_reported() {
        let (mut link, _) = spawn(&["sh", "-c", "exit 3"]);
        assert_eq!(link.source.next(), Read::Eof);
        let exit = link.control.wait();
        assert_eq!(
            (exit.clean, exit.description.as_str()),
            (false, "exit status 3")
        );
    }

    #[test]
    fn oversized_lines_are_reported_without_buffering_them() {
        let (mut link, _) = spawn(&[
            "sh",
            "-c",
            "head -c 100000 /dev/zero | tr '\\0' x; echo; echo after",
        ]);
        match link.source.next() {
            Read::Line(Line::Oversize { len, .. }) => assert_eq!(len, 100_000),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            link.source.next(),
            Read::Line(Line::Complete(b"after".to_vec()))
        );
        assert_eq!(link.source.next(), Read::Eof);
    }

    #[test]
    fn the_environment_is_minimal() {
        let (mut link, _) = spawn(&["sh", "-c", "env | sort"]);
        let mut seen = Vec::new();
        while let Read::Line(Line::Complete(l)) = link.source.next() {
            seen.push(String::from_utf8(l).unwrap());
        }
        assert!(seen.iter().any(|l| l.starts_with("PATH=")));
        for l in &seen {
            let name = l.split('=').next().unwrap();
            assert!(
                ["PATH", "PWD", "SHLVL", "_", "OLDPWD"].contains(&name),
                "unexpected variable {l}"
            );
        }
    }

    #[test]
    fn environment_building() {
        let mut c = config(&["x"]);
        c.inherit_env = vec!["A".into(), "B".into(), "UNSET".into()];
        c.env = vec![("B".into(), "from-config".into()), ("C".into(), "3".into())];
        let parent = |n: &str| match n {
            "A" => Some("from-parent".to_string()),
            "B" => Some("parent-b".to_string()),
            "SECRET" => Some("never".to_string()),
            _ => None,
        };
        let env = ProcessSpawner::environment(&c, &parent);
        assert_eq!(env.len(), 3);
        assert_eq!(env["A"], "from-parent");
        assert_eq!(env["B"], "from-config", "configured values win");
        assert!(!env.contains_key("SECRET") && !env.contains_key("UNSET"));
    }

    #[test]
    fn the_working_directory_is_applied() {
        let mut c = config(&["sh", "-c", "pwd"]);
        c.cwd = Some("/".into());
        let log = Arc::new(VecLogger::default());
        let mut link = ProcessSpawner::new(c, log).spawn().unwrap();
        assert_eq!(
            link.source.next(),
            Read::Line(Line::Complete(b"/".to_vec()))
        );
    }

    #[test]
    fn stderr_is_logged_escaped() {
        let (mut link, log) = spawn(&[
            "sh",
            "-c",
            "printf 'oops \\033[31mred\\033[0m\\n' >&2; echo done",
        ]);
        assert_eq!(
            link.source.next(),
            Read::Line(Line::Complete(b"done".to_vec()))
        );
        for _ in 0..200 {
            if log.contains("oops") {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            log.contains("upstream stderr: oops \\u{1b}[31mred"),
            "{:?}",
            log.lines()
        );
        assert!(!log.lines().iter().any(|(_, m)| m.contains('\u{1b}')));
    }

    #[test]
    fn terminate_kills_the_whole_tree() {
        // the shell starts a background sleep and then waits: terminating must take both
        let (mut link, _) = spawn(&["sh", "-c", "sleep 60 & echo $!; wait"]);
        let Read::Line(Line::Complete(pid)) = link.source.next() else {
            panic!()
        };
        let pid: i32 = String::from_utf8(pid).unwrap().trim().parse().unwrap();
        link.control.terminate();
        let exit = link.control.wait();
        assert!(!exit.clean);
        let mut gone = false;
        for _ in 0..100 {
            if !std::path::Path::new(&format!("/proc/{pid}")).exists()
                || std::fs::read_to_string(format!("/proc/{pid}/stat"))
                    .is_ok_and(|s| s.contains(") Z"))
            {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(gone, "the grandchild {pid} survived");
    }

    #[test]
    fn a_child_that_ignores_term_is_killed_after_the_grace_period() {
        let (link, _) = spawn(&["sh", "-c", "trap '' TERM; while :; do sleep 1; done"]);
        std::thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        link.control.terminate();
        let exit = link.control.wait();
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "the grace period was not waited out"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(exit.description.contains("signal 9"), "{exit:?}");
        link.control.terminate();
    }

    #[test]
    fn a_missing_program_is_a_spawn_error() {
        let log = Arc::new(VecLogger::default());
        let err = ProcessSpawner::new(config(&["/nonexistent/definitely-not-here"]), log)
            .spawn()
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn resource_limits_reach_the_child() {
        let mut c = config(&["sh", "-c", "ulimit -n"]);
        c.limits.max_open_files = Some(33);
        let log = Arc::new(VecLogger::default());
        let mut link = ProcessSpawner::new(c, log).spawn().unwrap();
        assert_eq!(
            link.source.next(),
            Read::Line(Line::Complete(b"33".to_vec()))
        );
    }
}
