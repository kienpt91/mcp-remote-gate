//! The audit log file: append-only JSON lines, readable by the owner only.

use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use gate_app::ports::AuditSink;
use gate_domain::audit::AuditRecord;

pub struct FileAudit {
    file: Mutex<File>,
    healthy: AtomicBool,
}

impl FileAudit {
    /// Opens `path` for appending, creating it with mode 0600. The directory must exist.
    pub fn open(path: &Path) -> io::Result<FileAudit> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        Ok(FileAudit {
            file: Mutex::new(file),
            healthy: AtomicBool::new(true),
        })
    }
}

impl AuditSink for FileAudit {
    fn record(&self, record: &AuditRecord) -> Result<(), String> {
        let mut line = record.to_line();
        line.push('\n');
        // one write call per record: with O_APPEND the line lands whole at the end of the file
        let result = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .write_all(line.as_bytes());
        match result {
            Ok(()) => {
                self.healthy.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(e) => {
                self.healthy.store(false, Ordering::SeqCst);
                Err(e.to_string())
            }
        }
    }
}

impl FileAudit {
    /// False after a failed write.
    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
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
    fn a_failing_write_marks_the_sink_unhealthy_until_a_write_succeeds() {
        // /dev/full accepts the open and fails every write with ENOSPC
        let Ok(audit) = FileAudit::open(Path::new("/dev/full")) else {
            return;
        };
        assert!(audit.record(&record(1)).is_err());
        assert!(!audit.healthy());
    }

    #[test]
    fn a_missing_directory_is_an_error() {
        assert!(FileAudit::open(Path::new("/nonexistent-dir-for-gate-tests/audit.jsonl")).is_err());
    }
}
