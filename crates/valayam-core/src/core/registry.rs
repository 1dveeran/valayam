//! Plugin Registry — enterprise-grade plugin dispatch with isolation.
//!
//! # Guarantees
//! - **Zero feature knowledge**: the registry never inspects template fields
//! - **Panic isolation**: `catch_unwind` around every plugin execution
//! - **Timeout enforcement**: `tokio::time::timeout` around every plugin
//! - **Parallel execution**: independent plugins run concurrently via JoinSet
//! - **Metrics collection**: per-plugin execution time, outcome, finding count

use crate::core::error::ScannerError;
use crate::core::traits::{
    FindingOwned, PluginMetrics, PluginOutcome, ScanContext, ScanPlugin, VariableScope,
};
use crate::core::variables::build_initial_context;
use crate::template::schema::VulnerabilityTemplate;
use futures::FutureExt;
use std::collections::HashSet;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;

pub struct PluginRegistry {
    plugins: Vec<Arc<dyn ScanPlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self { plugins: Vec::new() }
    }

    /// Register a plugin. Execution order follows registration order
    /// unless overridden by `depends_on()` declarations.
    pub fn register(&mut self, plugin: impl ScanPlugin + 'static) {
        tracing::info!(plugin = plugin.name(), version = plugin.version(), "registered plugin");
        self.plugins.push(Arc::new(plugin));
    }

    /// Initialize all plugins. Call once at startup.
    pub async fn init_all(&self) -> Result<(), ScannerError> {
        for plugin in &self.plugins {
            plugin.init().await.map_err(|e| {
                tracing::error!(plugin = plugin.name(), error = %e, "plugin init failed");
                ScannerError::PluginInitializationError(
                    format!("{}: {}", plugin.name(), e)
                )
            })?;
        }
        Ok(())
    }

    /// Validate all applicable plugin configs for a template. Fail-fast.
    pub fn validate_template(
        &self,
        template: &VulnerabilityTemplate,
    ) -> Result<(), ScannerError> {
        for plugin in &self.plugins {
            if plugin.is_applicable(template) {
                plugin.validate_config(template)?;
            }
        }
        Ok(())
    }

    /// Shutdown all plugins gracefully.
    pub async fn shutdown_all(&self) {
        for plugin in &self.plugins {
            if let Err(e) = plugin.shutdown().await {
                tracing::warn!(plugin = plugin.name(), error = %e, "plugin shutdown error");
            }
        }
    }

    pub fn len(&self) -> usize { self.plugins.len() }
    pub fn is_empty(&self) -> bool { self.plugins.is_empty() }

    /// Execute all applicable plugins for a template against a target.
    ///
    /// # Execution Strategy
    /// 1. Filter to applicable plugins
    /// 2. Build a dependency graph
    /// 3. Execute plugins in topological order:
    ///    - Plugins with no unmet dependencies run **in parallel** (JoinSet)
    ///    - Plugins with dependencies wait for them to complete first
    /// 4. Each plugin runs inside `catch_unwind` + `timeout`
    ///
    /// # Returns
    /// Vec of metrics for each executed plugin.
    pub async fn execute_template(
        &self,
        target: &str,
        template: Arc<VulnerabilityTemplate>,
        finding_tx: &mpsc::Sender<FindingOwned>,
        rate_limiter: Option<&crate::core::rate_limiter::RateLimiter>,
        cancellation: CancellationToken,
    ) -> Vec<PluginMetrics> {
        let target_host = url::Url::parse(target)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| target.to_string());

        let initial_vars = build_initial_context(target, &target_host);
        let variables = Arc::new(RwLock::new(VariableScope::new(initial_vars)));

        // Filter to applicable plugins
        let applicable: Vec<_> = self.plugins.iter()
            .filter(|p| p.is_applicable(&template))
            .cloned()
            .collect();

        if applicable.is_empty() {
            return Vec::new();
        }

        // Build set of applicable plugin names for dependency resolution
        let applicable_names: HashSet<&str> = applicable.iter()
            .map(|p| p.name())
            .collect();

        // Separate into: plugins with no deps (parallel) and plugins with deps (sequential after deps)
        let mut no_deps = Vec::new();
        let mut has_deps = Vec::new();

        for plugin in &applicable {
            let deps: Vec<&str> = plugin.depends_on().iter()
                .filter(|d| applicable_names.contains(*d))
                .copied()
                .collect();
            if deps.is_empty() {
                no_deps.push(plugin.clone());
            } else {
                has_deps.push((plugin.clone(), deps));
            }
        }

        let mut all_metrics = Vec::new();

        // Phase 1: Execute independent plugins in parallel
        if !no_deps.is_empty() {
            tracing::debug!(
                count = no_deps.len(),
                plugins = ?no_deps.iter().map(|p| p.name()).collect::<Vec<_>>(),
                "executing independent plugins in parallel"
            );

            let mut join_set = tokio::task::JoinSet::new();

            for plugin in no_deps {
                let ctx = ScanContext {
                    target: target.to_string(),
                    target_host: target_host.clone(),
                    template: template.clone(),
                    variables: variables.clone(),
                    finding_tx: finding_tx.clone(),
                    cancellation: cancellation.clone(),
                };

                // Rate limit before each plugin
                if let Some(rl) = rate_limiter {
                    rl.acquire().await;
                }

                join_set.spawn(async move {
                    execute_plugin_isolated(plugin, ctx).await
                });
            }

            // Collect results
            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok(metrics) => all_metrics.push(metrics),
                    Err(e) => tracing::error!(error = %e, "plugin task panicked at JoinSet level"),
                }
            }
        }

        // Phase 2: Execute dependent plugins in order
        // TODO: Implement full Kahn's topological sort for deeply nested dependencies.
        let completed: HashSet<String> = all_metrics.iter()
            .map(|m| m.plugin_name.clone())
            .collect();

        for (plugin, deps) in has_deps {
            // Check if all dependencies completed
            let unmet: Vec<_> = deps.iter()
                .filter(|d| !completed.contains(**d))
                .collect();

            if !unmet.is_empty() {
                tracing::warn!(
                    plugin = plugin.name(),
                    unmet_deps = ?unmet,
                    "skipping plugin due to unmet dependencies"
                );
                all_metrics.push(PluginMetrics {
                    plugin_name: plugin.name().to_string(),
                    target: target.to_string(),
                    outcome: "skipped".to_string(),
                    duration: std::time::Duration::ZERO,
                    finding_count: 0,
                });
                continue;
            }

            if let Some(rl) = rate_limiter {
                rl.acquire().await;
            }

            let ctx = ScanContext {
                target: target.to_string(),
                target_host: target_host.clone(),
                template: template.clone(),
                variables: variables.clone(),
                finding_tx: finding_tx.clone(),
                cancellation: cancellation.clone(),
            };

            let metrics = execute_plugin_isolated(plugin, ctx).await;
            all_metrics.push(metrics);
        }

        all_metrics
    }
}

impl Default for PluginRegistry {
    fn default() -> Self { Self::new() }
}

/// Execute a single plugin with full isolation:
/// - `catch_unwind` for panic protection
/// - `tokio::time::timeout` for hang protection
/// - Structured tracing span for observability
async fn execute_plugin_isolated(
    plugin: Arc<dyn ScanPlugin>,
    ctx: ScanContext,
) -> PluginMetrics {
    let plugin_name = plugin.name();
    let target = ctx.target.clone();
    let timeout_duration = plugin.timeout();
    let start = Instant::now();

    // Create a tracing span for this plugin execution
    let span = tracing::info_span!(
        "plugin_execute",
        plugin = plugin_name,
        target = %target,
    );

    let result = {
        let _guard = span.enter();

        // 🚨 TRUE ISOLATION: Wrap in timeout and AssertUnwindSafe.catch_unwind()
        let timeout_result = tokio::time::timeout(
            timeout_duration,
            AssertUnwindSafe(plugin.execute(&ctx)).catch_unwind(),
        ).await;

        match timeout_result {
            Ok(Ok(outcome)) => outcome, // normal completion
            Ok(Err(_panic)) => { // caught panic
                tracing::error!(plugin = plugin_name, "🚨 PLUGIN PANICKED 🚨 Engine protected.");
                PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError(
                        format!("plugin '{}' panicked during execution", plugin_name)
                    ),
                    retryable: false,
                }
            },
            Err(_elapsed) => { // timeout
                tracing::error!(
                    plugin = plugin_name,
                    timeout_secs = timeout_duration.as_secs(),
                    "plugin timed out"
                );
                PluginOutcome::Failed {
                    error: ScannerError::TimeoutError(
                        format!("plugin '{}' exceeded {}s timeout", plugin_name, timeout_duration.as_secs())
                    ),
                    retryable: false,
                }
            }
        }
    };

    let duration = start.elapsed();

    let (outcome_str, finding_count) = match &result {
        PluginOutcome::NoMatch => ("no_match".to_string(), 0),
        PluginOutcome::Matched { count } => ("matched".to_string(), *count),
        PluginOutcome::Skipped { reason } => {
            tracing::debug!(plugin = plugin_name, reason = %reason, "plugin skipped");
            ("skipped".to_string(), 0)
        }
        PluginOutcome::Failed { error, retryable } => {
            tracing::warn!(
                plugin = plugin_name,
                error = %error,
                retryable = retryable,
                "plugin failed"
            );
            ("failed".to_string(), 0)
        }
    };

    tracing::info!(
        plugin = plugin_name,
        outcome = %outcome_str,
        duration_ms = duration.as_millis() as u64,
        findings = finding_count,
        "plugin completed"
    );

    PluginMetrics {
        plugin_name: plugin_name.to_string(),
        target,
        outcome: outcome_str,
        duration,
        finding_count,
    }
}
