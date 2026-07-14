use super::server::OobServer;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

/// Executes OOB polling to check if an interaction has occurred.
pub struct OobExecutor;

impl OobExecutor {
    /// Polls the OOB server for a specific correlation ID until the timeout is reached.
    pub async fn wait_for_interaction(
        server: Arc<OobServer>,
        correlation_id: &str,
        timeout_secs: u64,
    ) -> bool {
        let max_retries = timeout_secs;
        for _ in 0..max_retries {
            if let Some(hits) = server.check_hits(correlation_id).await {
                if !hits.is_empty() {
                    return true;
                }
            }
            sleep(Duration::from_secs(1)).await;
        }
        false
    }
}
