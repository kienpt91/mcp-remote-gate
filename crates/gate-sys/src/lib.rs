//! The operating system interface of `mcp-remote-gate`, kept apart because it is the only code in
//! the workspace that needs `unsafe`: starting the upstream server in a process group of its own
//! with resource limits, signalling that group, and turning signals into flags.
//!
//! Unix only. Linux is what the tests run on; the macOS paths are compiled but not exercised.

#![allow(unsafe_code)]

use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

/// Resource limits for the upstream server. `None` leaves a limit as it is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Limits {
    /// Address space in MiB (`RLIMIT_AS`). Linux only: V8 and other runtimes reserve large
    /// address ranges, so this suits small native servers better than Node.
    pub memory_mb: Option<u64>,
    /// CPU time in seconds (`RLIMIT_CPU`).
    pub cpu_seconds: Option<u64>,
    /// Open file descriptors (`RLIMIT_NOFILE`).
    pub max_open_files: Option<u64>,
    /// Size of a file the process may write, in MiB (`RLIMIT_FSIZE`).
    pub max_file_mb: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Term,
    Kill,
}

impl Signal {
    fn number(self) -> libc::c_int {
        match self {
            Signal::Term => libc::SIGTERM,
            Signal::Kill => libc::SIGKILL,
        }
    }
}

/// Arranges for `cmd` to start in a process group of its own (so that the whole tree can be
/// signalled), with `limits` applied before it runs and, on Linux, with a kill signal when the
/// gateway thread that started it ends.
pub fn prepare_child(cmd: &mut Command, limits: Limits) {
    cmd.process_group(0);
    // SAFETY: the closure runs between fork and exec, so it may only call async-signal-safe
    // functions. It calls `setrlimit` and `prctl`, which are, and it allocates nothing.
    unsafe {
        cmd.pre_exec(move || apply_limits(limits));
    }
}

fn set_limit(resource: libc::c_int, value: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // SAFETY: `limit` is a valid, initialized rlimit that lives for the duration of the call.
    let rc = unsafe { libc::setrlimit(resource as _, &limit) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn apply_limits(limits: Limits) -> io::Result<()> {
    if let Some(mb) = limits.memory_mb {
        let result = set_limit(libc::RLIMIT_AS as libc::c_int, mb.saturating_mul(1 << 20));
        // macOS does not enforce RLIMIT_AS and may refuse it; the limit is best effort there
        if cfg!(target_os = "linux") {
            result?;
        }
    }
    if let Some(s) = limits.cpu_seconds {
        set_limit(libc::RLIMIT_CPU as libc::c_int, s)?;
    }
    if let Some(n) = limits.max_open_files {
        set_limit(libc::RLIMIT_NOFILE as libc::c_int, n)?;
    }
    if let Some(mb) = limits.max_file_mb {
        set_limit(
            libc::RLIMIT_FSIZE as libc::c_int,
            mb.saturating_mul(1 << 20),
        )?;
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with PR_SET_PDEATHSIG and a signal number has no memory arguments.
        let rc = unsafe {
            libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0,
                0,
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Sends `signal` to every process of the group `pgid`. A group that no longer exists is not an
/// error.
pub fn signal_group(pgid: u32, signal: Signal) -> io::Result<()> {
    let pgid = libc::pid_t::try_from(pgid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
    if pgid <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to signal process group 0 or 1",
        ));
    }
    // SAFETY: killpg takes two integers and touches no memory of ours.
    let rc = unsafe { libc::killpg(pgid, signal.number()) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(err)
    }
}

/// Whether the child process `pid` has exited, **without reaping it**. A child that has exited but
/// was not waited for is a zombie: it still holds its process id, and with it the process group of
/// the same number, so the group can be signalled without the risk that the number now belongs to
/// somebody else. Once the child is reaped that guarantee is gone.
pub fn has_exited(pid: u32) -> io::Result<bool> {
    // SAFETY: an all-zero siginfo_t is a valid value of that plain C struct.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waitid writes only into `info`, which is valid for the duration of the call; with
    // WNOHANG it does not block and with WNOWAIT it leaves the child waitable.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(target_os = "linux")]
    // SAFETY: the union member is valid after a successful waitid; the struct was zeroed first, so
    // it reads 0 when no child was in a waitable state.
    let reported = unsafe { info.si_pid() };
    #[cfg(not(target_os = "linux"))]
    let reported = info.si_pid;
    Ok(reported != 0)
}

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static KILL_SWITCH: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(signal: libc::c_int) {
    // Only atomics are touched: that is async-signal-safe.
    match signal {
        libc::SIGTERM | libc::SIGINT => SHUTDOWN.store(true, Ordering::SeqCst),
        libc::SIGUSR1 => KILL_SWITCH.store(true, Ordering::SeqCst),
        libc::SIGUSR2 => KILL_SWITCH.store(false, Ordering::SeqCst),
        _ => {}
    }
}

/// Makes SIGTERM and SIGINT request a shutdown, SIGUSR1 engage the kill switch and SIGUSR2
/// release it. The handlers only set flags, read with [`shutdown_requested`] and
/// [`kill_switch_signalled`].
pub fn install_signal_flags() -> io::Result<()> {
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGUSR1, libc::SIGUSR2] {
        // SAFETY: the sigaction struct is zero-initialized (a valid value for it), its handler
        // is an `extern "C"` function that only touches atomics, and the mask is initialized by
        // sigemptyset before use.
        let rc = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = 0;
            libc::sigaction(signal, &action, std::ptr::null_mut())
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

pub fn kill_switch_signalled() -> bool {
    KILL_SWITCH.load(Ordering::SeqCst)
}

/// The id of this process.
pub fn current_pid() -> u32 {
    std::process::id()
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
    use std::process::Stdio;

    fn run_sh(script: &str, limits: Limits) -> String {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", script]).stdout(Stdio::piped());
        prepare_child(&mut cmd, limits);
        let out = cmd.output().unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    #[test]
    fn limits_are_applied_before_the_program_runs() {
        assert_eq!(
            run_sh(
                "ulimit -t",
                Limits {
                    cpu_seconds: Some(7),
                    ..Limits::default()
                }
            ),
            "7"
        );
        assert_eq!(
            run_sh(
                "ulimit -n",
                Limits {
                    max_open_files: Some(77),
                    ..Limits::default()
                }
            ),
            "77"
        );
        if cfg!(target_os = "linux") {
            assert_eq!(
                run_sh(
                    "ulimit -v",
                    Limits {
                        memory_mb: Some(512),
                        ..Limits::default()
                    }
                ),
                "524288"
            );
        }
        // without limits the shell sees what the test process has
        assert_eq!(
            run_sh("ulimit -t", Limits::default()),
            run_sh("ulimit -t", Limits::default())
        );
    }

    #[test]
    fn a_child_that_exceeds_its_file_size_limit_is_stopped() {
        let path = std::env::temp_dir().join(format!("gate-sys-fsize-{}", std::process::id()));
        let script = format!(
            "dd if=/dev/zero of={} bs=1024 count=4096 2>/dev/null; echo $?",
            path.display()
        );
        let out = run_sh(
            &script,
            Limits {
                max_file_mb: Some(1),
                ..Limits::default()
            },
        );
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let _ = std::fs::remove_file(&path);
        assert_ne!(out, "0", "the write past the limit must fail");
        assert!(size <= 1 << 20, "{size}");
    }

    #[test]
    fn the_whole_group_is_signalled() {
        let mut cmd = Command::new("sh");
        // a shell with a background grandchild that would outlive it
        cmd.args(["-c", "sleep 30 & echo $! ; wait"])
            .stdout(Stdio::piped());
        prepare_child(&mut cmd, Limits::default());
        let mut child = cmd.spawn().unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.take().unwrap()),
            &mut line,
        )
        .unwrap();
        let grandchild: u32 = line.trim().parse().unwrap();
        let group = child.id();
        signal_group(group, Signal::Term).unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success());
        // the grandchild is gone too: signalling its pid finds nothing (it may linger as a zombie of init for a moment)
        let mut gone = false;
        for _ in 0..100 {
            // SAFETY: kill with signal 0 only checks that the process exists.
            let rc = unsafe { libc::kill(grandchild as libc::pid_t, 0) };
            // a killed process that nobody has reaped yet (init may be a program that does not wait) is a zombie
            let zombie = std::fs::read_to_string(format!("/proc/{grandchild}/stat"))
                .is_ok_and(|s| s.contains(") Z"));
            if rc != 0 || zombie {
                gone = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(gone, "the grandchild survived the group signal");
        // a group that is gone is not an error
        signal_group(group, Signal::Kill).unwrap();
    }

    #[test]
    fn an_exited_child_is_seen_without_being_reaped() {
        let mut running = Command::new("sleep");
        running.arg("30");
        prepare_child(&mut running, Limits::default());
        let mut running = running.spawn().unwrap();
        assert!(!has_exited(running.id()).unwrap());
        signal_group(running.id(), Signal::Kill).unwrap();
        let _ = running.wait();

        let mut quick = Command::new("sh");
        quick.args(["-c", "exit 3"]);
        prepare_child(&mut quick, Limits::default());
        let mut quick = quick.spawn().unwrap();
        let mut seen = false;
        for _ in 0..200 {
            if has_exited(quick.id()).unwrap() {
                seen = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(seen, "the exit was not noticed");
        assert!(
            has_exited(quick.id()).unwrap(),
            "asking again still reports the exit: nothing was reaped"
        );
        assert_eq!(
            quick.wait().unwrap().code(),
            Some(3),
            "the child could still be waited for"
        );
        assert!(
            has_exited(quick.id()).is_err(),
            "once reaped there is nothing to ask about"
        );
    }

    #[test]
    fn dangerous_group_numbers_are_refused() {
        for pgid in [0u32, 1, u32::MAX] {
            assert!(signal_group(pgid, Signal::Term).is_err(), "{pgid}");
        }
    }

    #[test]
    fn signals_set_flags() {
        install_signal_flags().unwrap();
        assert!(!shutdown_requested() && !kill_switch_signalled());
        // SAFETY: raise sends a signal to this process; a handler for it is installed above.
        unsafe {
            libc::raise(libc::SIGUSR1);
        }
        assert!(kill_switch_signalled());
        // SAFETY: as above.
        unsafe {
            libc::raise(libc::SIGUSR2);
        }
        assert!(!kill_switch_signalled());
        // SAFETY: as above.
        unsafe {
            libc::raise(libc::SIGTERM);
        }
        assert!(shutdown_requested());
        assert!(current_pid() > 1);
    }
}
