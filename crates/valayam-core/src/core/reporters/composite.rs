use crate::core::traits::{Reporter, FindingOwned};

/// Fans out findings to multiple reporters (e.g., Console + JSONL simultaneously).
pub struct CompositeReporter {
    reporters: Vec<Box<dyn Reporter>>,
}

impl CompositeReporter {
    pub fn new(reporters: Vec<Box<dyn Reporter>>) -> Self {
        Self { reporters }
    }
}

#[async_trait::async_trait]
impl Reporter for CompositeReporter {
    async fn process_finding(&self, finding: &FindingOwned) -> Result<(), std::io::Error> {
        for reporter in &self.reporters {
            if let Err(e) = reporter.process_finding(finding).await {
                tracing::error!(reporter = ?std::any::type_name_of_val(reporter), error = %e, "reporter failed");
                // Continue to other reporters — don't let one failure stop all output
            }
        }
        Ok(())
    }

    async fn flush(&self) -> Result<(), std::io::Error> {
        for reporter in &self.reporters {
            let _ = reporter.flush().await;
        }
        Ok(())
    }
}
