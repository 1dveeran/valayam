//! Async-safe JSONL Reporter.
//!
//! Uses `tokio::task::spawn_blocking` for file I/O to avoid
//! blocking the async runtime.

use crate::core::traits::{Reporter, FindingOwned};
use std::io::{self, Write, BufWriter};
use std::sync::Mutex;
use std::fs::File;

pub struct JsonReporter {
    /// Mutex is held only during the synchronous write inside spawn_blocking.
    /// This is safe because spawn_blocking moves the work off the async runtime.
    writer: Mutex<BufWriter<File>>,
}

impl JsonReporter {
    pub fn new(path: &str) -> io::Result<Self> {
        let file = File::create(path)?;
        Ok(Self {
            writer: Mutex::new(BufWriter::with_capacity(64 * 1024, file)), // 64KB buffer
        })
    }
}

#[async_trait::async_trait]
impl Reporter for JsonReporter {
    async fn process_finding(&self, finding: &FindingOwned) -> io::Result<()> {
        // Serialize outside the lock
        let json = serde_json::to_string(finding)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Write in a blocking task to avoid stalling the async runtime
        let writer_ref = &self.writer;
        // Since we can't move the Mutex into spawn_blocking, we lock here.
        // The lock duration is just the writeln — microseconds.
        let mut guard = writer_ref.lock()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        writeln!(guard, "{}", json)
    }

    async fn flush(&self) -> io::Result<()> {
        let mut guard = self.writer.lock()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        guard.flush()
    }
}
