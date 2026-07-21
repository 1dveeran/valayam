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

    /// Access the underlying registry (for testing/inspection).
    pub fn registry(&self) -> &PluginRegistry {
        &self.registry
    }

    /// Access the rate limiter reference (if set).
    pub fn rate_limiter_ref(&self) -> Option<&Arc<RateLimiter>> {
        self.rate_limiter.as_ref()
    }

    /// Access the cancellation token (for testing).
    pub fn cancellation_token(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Access the finding sender (for testing).
    pub fn finding_tx(&self) -> &mpsc::Sender<FindingOwned> {
        &self.finding_tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::traits::{ScanPlugin, PluginOutcome, ScanContext};
    use crate::core::registry::PluginRegistry;
    use crate::template::schema::{TemplateInfo, VulnerabilityTemplate};

    struct MockPlugin;

    #[async_trait::async_trait]
    impl ScanPlugin for MockPlugin {
        fn name(&self) -> &str { "mock" }
        fn is_applicable(&self, _: &VulnerabilityTemplate) -> bool { true }
        async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
            let _ = ctx.finding_tx.send(FindingOwned {
                template_id: "mock-001".into(),
                template_name: "Mock".into(),
                severity: "info".into(),
                target: ctx.target.clone(),
                matched_at: "test".into(),
                description: None,
                solution: None,
                extracted_data: None,
                metadata: Default::default(),
            }).await;
            PluginOutcome::Matched { count: 1 }
        }
    }

    fn dummy_template() -> Arc<VulnerabilityTemplate> {
        Arc::new(VulnerabilityTemplate {
            id: "test".into(),
            info: TemplateInfo {
                name: "Test".into(),
                severity: "info".into(),
                description: None,
                compliance: Default::default(),
            },
            ..VulnerabilityTemplate::default()
        })
    }

    #[test]
    fn test_executor_new() {
        let (tx, _rx) = mpsc::channel(10);
        let registry = Arc::new(PluginRegistry::new());
        let cancel = CancellationToken::new();
        let executor = ScanExecutor::new(tx.clone(), registry.clone(), None, cancel.clone());

        // Verify accessor methods
        assert!(executor.rate_limiter_ref().is_none());
        assert!(!executor.cancellation_token().is_cancelled());
        cancel.cancel();
        assert!(executor.cancellation_token().is_cancelled());
    }

    #[test]
    fn test_executor_new_with_rate_limiter() {
        let (tx, _rx) = mpsc::channel(10);
        let registry = Arc::new(PluginRegistry::new());
        let cancel = CancellationToken::new();
        let rl = Arc::new(crate::core::rate_limiter::RateLimiter::new_simple(100));
        let executor = ScanExecutor::new(tx.clone(), registry.clone(), Some(rl.clone()), cancel);

        assert!(executor.rate_limiter_ref().is_some());
    }

    #[tokio::test]
    async fn test_executor_execute_delegates_to_registry() {
        let (tx, _rx) = mpsc::channel(10);
        let registry = Arc::new(PluginRegistry::new());
        registry.register(MockPlugin);
        let cancel = CancellationToken::new();
        let executor = ScanExecutor::new(tx.clone(), registry.clone(), None, cancel.clone());

        let metrics = executor.execute("https://example.com", dummy_template()).await;
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].plugin_name, "mock");
        assert_eq!(metrics[0].outcome, crate::core::traits::PluginOutcomeKind::Matched);
    }

    #[tokio::test]
    async fn test_executor_cancellation_propagation() {
        let (tx, _rx) = mpsc::channel(10);
        let registry = Arc::new(PluginRegistry::new());
        registry.register(MockPlugin);
        let cancel = CancellationToken::new();
        let executor = ScanExecutor::new(tx.clone(), registry.clone(), None, cancel.clone());

        assert!(!executor.cancellation_token().is_cancelled());
        cancel.cancel();
        assert!(executor.cancellation_token().is_cancelled());

        // Template still executes (cancellation is per-plugin, checked by individual plugins)
        let metrics = executor.execute("https://example.com", dummy_template()).await;
        assert_eq!(metrics.len(), 1);
    }

    #[tokio::test]
    async fn test_executor_finding_channel_wiring() {
        let (tx, mut rx) = mpsc::channel(10);
        let registry = Arc::new(PluginRegistry::new());
        registry.register(MockPlugin);
        let cancel = CancellationToken::new();
        let executor = ScanExecutor::new(tx.clone(), registry.clone(), None, cancel);

        executor.execute("https://example.com", dummy_template()).await;
        let received = rx.try_recv();
        assert!(received.is_ok());
        let finding = received.unwrap();
        assert_eq!(finding.template_id, "mock-001");
    }
}
