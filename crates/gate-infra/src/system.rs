//! Small adapters over the operating system: the clock, the kill switch, the log and entropy.

use std::io::{self, Read as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use gate_app::ports::{Clock, KillSwitch, Level, Logger};
use gate_domain::audit::rfc3339_millis;
use gate_domain::sanitize::escape_control;

pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    pub fn new() -> SystemClock {
        SystemClock {
            start: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        SystemClock::new()
    }
}

impl Clock for SystemClock {
    fn mono_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

/// The kill switch is engaged while the file exists or after SIGUSR1 (released by SIGUSR2). If
/// the file cannot be inspected for a reason other than its absence, the switch counts as
/// engaged: the safe answer is "off".
pub struct FileKillSwitch {
    path: Option<PathBuf>,
    signals: bool,
}

impl FileKillSwitch {
    pub fn new(path: Option<PathBuf>, signals: bool) -> FileKillSwitch {
        FileKillSwitch { path, signals }
    }
}

impl KillSwitch for FileKillSwitch {
    fn engaged(&self) -> bool {
        if self.signals && gate_sys::kill_switch_signalled() {
            return true;
        }
        match &self.path {
            None => false,
            Some(path) => match std::fs::symlink_metadata(path) {
                Ok(_) => true,
                Err(e) => e.kind() != io::ErrorKind::NotFound,
            },
        }
    }
}

/// Writes `time LEVEL message` lines to standard error. Messages are escaped once more here so
/// that no caller can put a control character into the log.
pub struct StderrLogger {
    clock: Arc<dyn Clock>,
}

impl StderrLogger {
    pub fn new(clock: Arc<dyn Clock>) -> StderrLogger {
        StderrLogger { clock }
    }
}

impl Logger for StderrLogger {
    fn log(&self, level: Level, message: &str) {
        let name = match level {
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        };
        eprintln!(
            "{} {name} {}",
            rfc3339_millis(self.clock.unix_ms()),
            escape_control(message, 600)
        );
    }
}

/// `N` random bytes from the operating system.
pub fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut out = [0u8; N];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut out)?;
    Ok(out)
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
    use crate::testutil::TempDir;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_clock_moves_forward() {
        let c = SystemClock::default();
        let a = c.mono_ms();
        c.sleep_ms(15);
        assert!(c.mono_ms() >= a + 10);
        assert!(c.unix_ms() > 1_700_000_000_000);
    }

    #[test]
    fn the_kill_switch_follows_the_file() {
        let dir = TempDir::new("kill");
        let path = dir.join("KILL");
        let ks = FileKillSwitch::new(Some(path.clone()), false);
        assert!(!ks.engaged());
        std::fs::write(&path, "").unwrap();
        assert!(ks.engaged());
        std::fs::remove_file(&path).unwrap();
        assert!(!ks.engaged());
        assert!(!FileKillSwitch::new(None, false).engaged());
    }

    #[test]
    fn a_dangling_symlink_still_engages_the_switch() {
        let dir = TempDir::new("killlink");
        let path = dir.join("KILL");
        std::os::unix::fs::symlink(dir.join("nowhere"), &path).unwrap();
        assert!(FileKillSwitch::new(Some(path), false).engaged());
    }

    #[test]
    fn an_unreadable_location_fails_closed() {
        let dir = TempDir::new("killperm");
        let locked = dir.join("locked");
        std::fs::create_dir(&locked).unwrap();
        let path = locked.join("KILL");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let engaged = FileKillSwitch::new(Some(path), false).engaged();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        // running as root bypasses the permission, then the file is simply absent
        if std::fs::read_dir(&locked).is_ok() && unsafe_free_is_root() {
            return;
        }
        assert!(engaged);
    }

    fn unsafe_free_is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .is_ok_and(|s| s.lines().any(|l| l.starts_with("Uid:\t0\t")))
    }

    #[test]
    fn entropy_differs_between_calls() {
        let a: [u8; 32] = random_bytes().unwrap();
        let b: [u8; 32] = random_bytes().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
