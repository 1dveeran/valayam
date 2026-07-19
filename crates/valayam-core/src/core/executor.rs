//! ScanExecutor — the Producer in the MPSC architecture.
//!
//! Agnostic to what scans exist and how findings are logged.

use crate::core::rate_limiter::RateLimiter;
use crate::core::registry::PluginRegistry;
use crate::core::traits::{FindingOwned, PluginMetrics};
use crate::template::schema::VulnerabilityTemplate;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct ScanExecutor {
    finding_tx: mpsc::Sender<FindingOwned>,
    registry: Arc<PluginRegistry>,
    rate_limiter: Option<Arc<RateLimiter>>,
    cancellation: CancellationToken,
}

impl ScanExecutor {
    pub fn new(
        finding_tx: mpsc::Sender<FindingOwned>,
        registry: Arc<PluginRegistry>,
        rate_limiter: Option<Arc<RateLimiter>>,
        cancellation: CancellationToken,
    ) -> Self {
        Self { finding_tx, registry, rate_limiter, cancellation }
    }

    /// Execute a template against a target. Returns per-plugin metrics.
    pub async fn execute(
        &self,
        target: &str,
        template: Arc<VulnerabilityTemplate>,
    ) -> Vec<PluginMetrics> {
        self.registry.execute_template(
            target,
            template,
            &self.finding_tx,
            self.rate_limiter.as_deref(),
            self.cancellation.clone(),
        ).await
    }
}
