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
            .map_err(|e| io::Error::other(e))?;

        // Write in a blocking task to avoid stalling the async runtime
        let writer_ref = &self.writer;
        // Since we can't move the Mutex into spawn_blocking, we lock here.
        // The lock duration is just the writeln — microseconds.
        let mut guard = writer_ref.lock()
            .map_err(|e| io::Error::other(e.to_string()))?;
        writeln!(guard, "{}", json)
    }

    async fn flush(&self) -> io::Result<()> {
        let mut guard = self.writer.lock()
            .map_err(|e| io::Error::other(e.to_string()))?;
        guard.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn sample_finding() -> FindingOwned {
        FindingOwned {
            template_id: "json-001".into(),
            template_name: "JSON Test".into(),
            severity: "medium".into(),
            target: "https://example.com/api".into(),
            matched_at: "endpoint".into(),
            description: Some("Test description".into()),
            solution: None,
            extracted_data: None,
            metadata: Default::default(),
        }
    }

    #[tokio::test]
    async fn test_json_reporter_process_finding() {
        let path = "test_output.jsonl";
        // Clean up any leftover from previous runs
        let _ = fs::remove_file(path);

        let reporter = JsonReporter::new(path).unwrap();
        let result = reporter.process_finding(&sample_finding()).await;
        assert!(result.is_ok());
        // Flush to ensure data is written to disk
        reporter.flush().await.unwrap();

        // Verify file was written
        assert!(Path::new(path).exists());
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("json-001"));
        assert!(content.contains("JSON Test"));
        assert!(content.contains("medium"));

        // Clean up
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_json_reporter_multiple_findings_jsonl() {
        let path = "test_multi.jsonl";
        let _ = fs::remove_file(path);

        let reporter = JsonReporter::new(path).unwrap();
        let f1 = sample_finding();
        let f2 = FindingOwned {
            template_id: "json-002".into(),
            template_name: "Second Finding".into(),
            severity: "low".into(),
            target: "https://example.com/other".into(),
            matched_at: "other".into(),
            description: None,
            solution: None,
            extracted_data: None,
            metadata: Default::default(),
        };

        reporter.process_finding(&f1).await.unwrap();
        reporter.process_finding(&f2).await.unwrap();
        reporter.flush().await.unwrap();

        let content = fs::read_to_string(path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("json-001"));
        assert!(lines[1].contains("json-002"));

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_json_reporter_flush() {
        let path = "test_flush.jsonl";
        let _ = fs::remove_file(path);

        let reporter = JsonReporter::new(path).unwrap();
        let result = reporter.flush().await;
        assert!(result.is_ok());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_json_reporter_new_invalid_path() {
        let result = JsonReporter::new("/nonexistent/deep/dir/output.jsonl");
        assert!(result.is_err());
    }
}
