//! Helpers for the tests of this crate and of the crates above it (not used by the program).

#![allow(clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A fresh directory under the system temp dir, removed when dropped.
pub struct TempDir {
    path: PathBuf,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

impl TempDir {
    pub fn new(label: &str) -> TempDir {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("gate-{label}-{}-{n}", std::process::id()));
        // a leftover of a crashed run with the same pid is replaced
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)
            .unwrap_or_else(|e| panic!("cannot create {}: {e}", path.display()));
        TempDir { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub fn write(&self, name: &str, content: &str) -> PathBuf {
        let p = self.join(name);
        std::fs::write(&p, content).unwrap_or_else(|e| panic!("cannot write {}: {e}", p.display()));
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
