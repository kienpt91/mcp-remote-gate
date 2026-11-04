//! The audit log file: append-only JSON lines, private to the owner, and honest about failures.
//!
//! What the file adapter guarantees, and what it does not:
//!
//! - The file is opened with `O_NOFOLLOW` (a symbolic link is refused), must be a regular file owned
//!   by the user running the gateway, and is created with mode 0600; a looser mode on a file that
//!   already exists is tightened to 0600 (the gateway reports it).
//! - Before every record the path is compared with the open file (device and inode). If the file was
//!   moved away (log rotation by rename) or deleted, the path is opened again and logging goes on in
//!   the new file; if the path now holds anything that cannot be opened safely, the record fails.
//! - A record is written with one `write` per line. After a failed write the log is *broken*: every
//!   further record fails until a recovery marker, larger than the record that failed, has been
//!   written and flushed to disk. A small record that happens to fit does not make a full disk
//!   healthy again, and a half-written line is ended before anything else follows it.
//! - Not guaranteed: protection against someone who can write to the directory or the file (the log
//!   is not tamper-evident), durability of each line across a power cut (lines are not synced one by
//!   one), or rotation by copy and truncate losing lines written in between.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use gate_app::ports::AuditSink;
use gate_domain::audit::{rfc3339_millis, AuditRecord};

/// The smallest recovery marker, in bytes: well above the size of an ordinary record.
const MIN_MARKER_BYTES: usize = 4096;

/// What the log needs from its destination besides `Write`: a way to force data to disk.
pub(crate) trait Durable {
    fn make_durable(&mut self) -> io::Result<()>;
}

impl Durable for File {
    fn make_durable(&mut self) -> io::Result<()> {
        self.sync_data()
    }
}

/// What is known after a failed write.
struct Broken {
    /// Part of a line may be in the file without its end.
    torn: bool,
    /// The size of the largest write that failed; recovery must prove that a bigger one works.
    largest_failed: usize,
}

/// The state machine of the log, independent of where the bytes go (so that a full disk can be
/// simulated in tests).
pub(crate) struct Trail<W: Write + Durable> {
    pub(crate) out: W,
    broken: Option<Broken>,
}

impl<W: Write + Durable> Trail<W> {
    pub(crate) fn new(out: W) -> Trail<W> {
        Trail { out, broken: None }
    }

    pub(crate) fn healthy(&self) -> bool {
        self.broken.is_none()
    }

    /// Notes a failure that happened outside a write (the file could not be found or opened).
    fn note_failure(&mut self) {
        if self.broken.is_none() {
            self.broken = Some(Broken {
                torn: false,
                largest_failed: 0,
            });
        }
    }

    /// Writes all of `bytes`; on failure returns the error and whether part of it was written.
    fn write_counted(&mut self, bytes: &[u8]) -> Result<(), (io::Error, bool)> {
        let mut done = 0usize;
        while done < bytes.len() {
            match self.out.write(bytes.get(done..).unwrap_or_default()) {
                Ok(0) => return Err((io::Error::from(io::ErrorKind::WriteZero), done > 0)),
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err((e, done > 0)),
            }
        }
        Ok(())
    }

    /// Appends `line` and a newline. `unix_ms` stamps the recovery marker if one is needed.
    pub(crate) fn append(&mut self, line: &str, unix_ms: u64) -> Result<(), String> {
        let mut bytes = Vec::with_capacity(line.len() + 1);
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
        if self.broken.is_some() {
            self.recover(unix_ms)?;
        }
        match self.write_counted(&bytes) {
            Ok(()) => Ok(()),
            Err((e, torn)) => {
                self.broken = Some(Broken {
                    torn,
                    largest_failed: bytes.len(),
                });
                Err(e.to_string())
            }
        }
    }

    /// Proves that the destination works again by writing, and flushing, a marker bigger than
    /// anything that failed.
    fn recover(&mut self, unix_ms: u64) -> Result<(), String> {
        let Some(broken) = &self.broken else {
            return Ok(());
        };
        let want = MIN_MARKER_BYTES.max(broken.largest_failed.saturating_mul(2));
        let head = format!(
            "{{\"v\":1,\"ts\":\"{}\",\"event\":\"audit_recovered\",\"pad\":\"",
            rfc3339_millis(unix_ms)
        );
        let tail = "\"}\n";
        let mut marker = String::with_capacity(want + 1);
        if broken.torn {
            marker.push('\n');
        }
        marker.push_str(&head);
        while marker.len() + tail.len() < want {
            marker.push(' ');
        }
        marker.push_str(tail);
        let result = self.write_counted(marker.as_bytes());
        let result = match result {
            Ok(()) => self.out.make_durable().map_err(|e| (e, false)),
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => {
                self.broken = None;
                Ok(())
            }
            Err((e, torn)) => {
                if let Some(b) = self.broken.as_mut() {
                    b.torn |= torn;
                }
                Err(format!("the audit log is still failing: {e}"))
            }
        }
    }
}

struct State {
    trail: Trail<File>,
    /// Device and inode of the file the trail writes to.
    ident: (u64, u64),
}

pub struct FileAudit {
    path: PathBuf,
    state: Mutex<State>,
    tightened: Option<u32>,
}

/// Opens `path` for appending and checks what was opened. Returns the file, its identity and the
/// mode it had if that was looser than 0600 (and was tightened).
fn open_checked(path: &Path) -> io::Result<(File, (u64, u64), Option<u32>)> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(gate_sys::NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::other("the audit path is not a regular file"));
    }
    if meta.uid() != gate_sys::effective_uid() {
        return Err(io::Error::other(
            "the audit file belongs to another user; refusing to write the audit log into it",
        ));
    }
    let mode = meta.mode() & 0o777;
    let tightened = if mode & 0o077 != 0 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Some(mode)
    } else {
        None
    };
    Ok((file, (meta.dev(), meta.ino()), tightened))
}

fn lock(m: &Mutex<State>) -> MutexGuard<'_, State> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FileAudit {
    /// Opens `path` for appending, creating it with mode 0600. The directory must exist.
    pub fn open(path: &Path) -> io::Result<FileAudit> {
        let (file, ident, tightened) = open_checked(path)?;
        Ok(FileAudit {
            path: path.to_path_buf(),
            state: Mutex::new(State {
                trail: Trail::new(file),
                ident,
            }),
            tightened,
        })
    }

    /// The mode the file had when it was opened, if that was looser than 0600 and was tightened.
    pub fn tightened_from(&self) -> Option<u32> {
        self.tightened
    }

    /// False after a failed write, until the recovery marker has been written.
    pub fn healthy(&self) -> bool {
        lock(&self.state).trail.healthy()
    }

    /// Makes sure the open file is still the file at the path; opens the path again if it moved.
    fn ensure_current(&self, st: &mut State) -> io::Result<()> {
        let same = std::fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.is_file() && (m.dev(), m.ino()) == st.ident);
        if same {
            return Ok(());
        }
        let (file, ident, _) = open_checked(&self.path)?;
        st.trail.out = file;
        st.ident = ident;
        Ok(())
    }
}

impl AuditSink for FileAudit {
    fn record(&self, record: &AuditRecord) -> Result<(), String> {
        let mut st = lock(&self.state);
        if let Err(e) = self.ensure_current(&mut st) {
            st.trail.note_failure();
            return Err(format!("the audit file cannot be used: {e}"));
        }
        st.trail.append(&record.to_line(), record.unix_ms)
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
    use crate::testutil::TempDir;
    use gate_domain::audit::Outcome;
    use gate_domain::json;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::Arc;

    fn record(n: u64) -> AuditRecord {
        AuditRecord {
            unix_ms: 1_730_000_000_000 + n,
            token: Some("t".into()),
            peer: None,
            method: "tools/call".into(),
            tool: Some("get_x".into()),
            outcome: Outcome::Allowed,
            reason: "ok".into(),
            duration_ms: n,
            request_bytes: 1,
            response_bytes: 2,
            arguments: None,
            suppressed: 0,
        }
    }

    #[test]
    fn records_are_appended_as_lines_and_the_file_is_private() {
        let dir = TempDir::new("audit");
        let path = dir.join("audit.jsonl");
        let audit = FileAudit::open(&path).unwrap();
        audit.record(&record(1)).unwrap();
        audit.record(&record(2)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            json::parse(lines[1])
                .unwrap()
                .get("duration_ms")
                .and_then(json::Value::as_u64),
            Some(2)
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(audit.healthy());
    }

    #[test]
    fn reopening_appends_instead_of_truncating() {
        let dir = TempDir::new("audit2");
        let path = dir.join("audit.jsonl");
        FileAudit::open(&path).unwrap().record(&record(1)).unwrap();
        FileAudit::open(&path).unwrap().record(&record(2)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    }

    #[test]
    fn concurrent_writers_never_interleave_lines() {
        let dir = TempDir::new("audit3");
        let path = dir.join("audit.jsonl");
        let audit = Arc::new(FileAudit::open(&path).unwrap());
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let audit = Arc::clone(&audit);
                std::thread::spawn(move || {
                    for i in 0..200 {
                        audit.record(&record(t * 1000 + i)).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1600);
        assert!(text.lines().all(|l| json::parse(l).is_ok()));
    }

    #[test]
    fn a_missing_directory_is_an_error() {
        assert!(FileAudit::open(Path::new("/nonexistent-dir-for-gate-tests/audit.jsonl")).is_err());
    }
    fn lines_of(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn a_pre_existing_loose_file_is_tightened_not_trusted() {
        let dir = TempDir::new("audit-mode");
        let path = dir.write("audit.jsonl", "{\"old\":true}\n");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let audit = FileAudit::open(&path).unwrap();
        assert_eq!(audit.tightened_from(), Some(0o644));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        audit.record(&record(1)).unwrap();
        let lines = lines_of(&path);
        assert_eq!(lines.len(), 2, "what was in the file is kept");
        assert_eq!(lines[0], "{\"old\":true}");
        // a file that was private already is left alone
        assert_eq!(FileAudit::open(&path).unwrap().tightened_from(), None);
    }

    #[test]
    fn a_symbolic_link_is_refused() {
        let dir = TempDir::new("audit-link");
        let target = dir.write("elsewhere.log", "keep\n");
        let link = dir.join("audit.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(FileAudit::open(&link).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep\n");
    }

    #[test]
    fn something_that_is_not_a_regular_file_is_refused() {
        let dir = TempDir::new("audit-dir");
        assert!(FileAudit::open(dir.path()).is_err());
    }

    #[test]
    fn a_file_moved_away_by_rotation_is_replaced_by_a_new_one() {
        let dir = TempDir::new("audit-rotate");
        let path = dir.join("audit.jsonl");
        let audit = FileAudit::open(&path).unwrap();
        audit.record(&record(1)).unwrap();
        std::fs::rename(&path, dir.join("audit.jsonl.1")).unwrap();
        audit.record(&record(2)).unwrap();
        audit.record(&record(3)).unwrap();
        assert_eq!(
            lines_of(&dir.join("audit.jsonl.1")).len(),
            1,
            "the old file has what came before"
        );
        assert_eq!(lines_of(&path).len(), 2, "the new file has what came after");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn a_deleted_file_is_recreated_and_the_record_is_not_lost() {
        let dir = TempDir::new("audit-unlink");
        let path = dir.join("audit.jsonl");
        let audit = FileAudit::open(&path).unwrap();
        audit.record(&record(1)).unwrap();
        std::fs::remove_file(&path).unwrap();
        audit.record(&record(2)).unwrap();
        assert_eq!(
            lines_of(&path).len(),
            1,
            "the record landed in a file somebody can find"
        );
    }

    #[test]
    fn a_file_replaced_by_a_symbolic_link_is_not_followed() {
        let dir = TempDir::new("audit-swap");
        let path = dir.join("audit.jsonl");
        let audit = FileAudit::open(&path).unwrap();
        audit.record(&record(1)).unwrap();
        let target = dir.write("target.log", "untouched\n");
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(
            audit.record(&record(2)).is_err(),
            "the call must not run without a trail"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched\n");
    }

    #[test]
    fn a_missing_directory_after_start_is_an_error_not_a_silent_loss() {
        let dir = TempDir::new("audit-gone");
        let sub = dir.join("logs");
        std::fs::create_dir(&sub).unwrap();
        let audit = FileAudit::open(&sub.join("audit.jsonl")).unwrap();
        audit.record(&record(1)).unwrap();
        std::fs::remove_dir_all(&sub).unwrap();
        assert!(audit.record(&record(2)).is_err());
        assert!(!audit.healthy());
    }

    /// A writer that behaves like a disk that is nearly full: writes up to \`limit\` bytes succeed,
    /// bigger ones fail after taking part of the data.
    struct NearlyFull {
        data: Vec<u8>,
        limit: usize,
        torn_bytes: usize,
        writes: usize,
        synced: usize,
    }

    impl std::io::Write for NearlyFull {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            if buf.len() > self.limit {
                // like a kernel: part of the data may be taken (a short write), the rest fails
                let take = self.torn_bytes.min(buf.len());
                if take > 0 {
                    self.data.extend_from_slice(&buf[..take]);
                    self.torn_bytes = 0;
                    return Ok(take);
                }
                return Err(std::io::Error::other("no space left on device"));
            }
            self.data.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Durable for NearlyFull {
        fn make_durable(&mut self) -> std::io::Result<()> {
            self.synced += 1;
            Ok(())
        }
    }

    fn full_disk(limit: usize, torn_bytes: usize) -> Trail<NearlyFull> {
        Trail::new(NearlyFull {
            data: Vec::new(),
            limit,
            torn_bytes,
            writes: 0,
            synced: 0,
        })
    }

    #[test]
    fn a_later_small_write_does_not_make_a_failed_log_healthy() {
        // records of 100 bytes fit; the record of 1,000 bytes does not
        let mut trail = full_disk(500, 0);
        let small = "s".repeat(100);
        let big = "b".repeat(1000);
        trail.append(&small, 1).unwrap();
        assert!(trail.append(&big, 2).is_err());
        assert!(!trail.healthy());
        // a small record would fit, but the condition that made the big one fail was not checked
        assert!(
            trail.append(&small, 3).is_err(),
            "the flag must not flip back on a small write"
        );
        assert!(!trail.healthy());
        assert!(
            !String::from_utf8_lossy(&trail.out.data).contains(&small.repeat(2)),
            "nothing was written as if all was well"
        );
    }

    #[test]
    fn the_log_recovers_once_a_write_as_large_as_the_failed_one_succeeds() {
        let mut trail = full_disk(500, 0);
        let big = "b".repeat(1000);
        assert!(trail.append(&big, 2).is_err());
        // the space comes back
        trail.out.limit = 1_000_000;
        trail.append("after", 3).unwrap();
        assert!(trail.healthy());
        let text = String::from_utf8_lossy(&trail.out.data).into_owned();
        assert!(text.contains("\"event\":\"audit_recovered\""), "{text}");
        assert!(text.trim_end().ends_with("after"));
        assert!(
            trail.out.synced >= 1,
            "the marker was made durable before the log was trusted again"
        );
        // the marker is bigger than the record that failed
        let marker = text
            .lines()
            .find(|l| l.contains("audit_recovered"))
            .unwrap();
        assert!(marker.len() >= 2 * big.len(), "{}", marker.len());
        assert!(json::parse(marker).is_ok());
    }

    #[test]
    fn a_torn_line_is_terminated_before_anything_else_is_written() {
        let mut trail = full_disk(500, 40);
        assert!(trail.append(&"x".repeat(1000), 1).is_err());
        trail.out.limit = 1_000_000;
        trail.append("{\"ok\":1}", 2).unwrap();
        let text = String::from_utf8_lossy(&trail.out.data).into_owned();
        let lines: Vec<&str> = text.lines().collect();
        assert!(
            lines[0].starts_with("xxxx") && lines[0].len() == 40,
            "the torn part stays on a line of its own"
        );
        assert!(lines
            .iter()
            .any(|l| l.contains("audit_recovered") && json::parse(l).is_ok()));
        assert_eq!(*lines.last().unwrap(), "{\"ok\":1}");
    }

    #[test]
    fn a_marker_that_fails_keeps_the_log_unhealthy() {
        let mut trail = full_disk(500, 0);
        assert!(trail.append(&"b".repeat(1000), 1).is_err());
        // space for the record is back but not for the (larger) marker
        trail.out.limit = 1200;
        assert!(trail.append("tiny", 2).is_err());
        assert!(!trail.healthy());
        trail.out.limit = 1_000_000;
        assert!(trail.append("tiny", 3).is_ok());
        assert!(trail.healthy());
    }
}
