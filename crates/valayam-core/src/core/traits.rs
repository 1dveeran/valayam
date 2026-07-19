//! Core trait definitions for the Valayam plugin architecture.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;

// ─── FindingOwned ───────────────────────────────────────────────────────

/// A vulnerability finding ready for channel transport and serialization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FindingOwned {
    pub template_id: String,
    pub template_name: String,
    pub severity: String,
    pub target: String,
    pub matched_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extracted_data: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl FindingOwned {
    /// Convert to legacy `ScanResult` for backward compatibility.
    #[must_use]
    pub fn into_scan_result(self) -> crate::core::result::ScanResult {
        crate::core::result::ScanResult {
            timestamp: chrono::Utc::now(),
            template_id: self.template_id,
            template_name: self.template_name,
            template_severity: self.severity,
            target: self.target,
            payload: self.matched_at,
            compliance: Default::default(),
            cvss_score: None,
            solution: None,
            reference: None,
            tags: Vec::new(),
        }
    }
}

// ─── VariableScope ──────────────────────────────────────────────────────

/// Namespaced variable context for template `{{placeholder}}` resolution.
#[derive(Debug, Clone, Default)]
pub struct VariableScope {
    global: HashMap<String, String>,
    scoped: HashMap<String, HashMap<String, String>>,
}

impl VariableScope {
    pub fn new(globals: HashMap<String, String>) -> Self {
        Self { global: globals, scoped: HashMap::new() }
    }
    pub fn set_global(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.global.insert(key.into(), value.into());
    }
    pub fn set(&mut self, plugin: &str, key: impl Into<String>, value: impl Into<String>) {
        self.scoped.entry(plugin.to_string()).or_default().insert(key.into(), value.into());
    }
    pub fn get(&self, key: &str) -> Option<&String> {
        if let Some(v) = self.global.get(key) { return Some(v); }
        for scope in self.scoped.values() {
            if let Some(v) = scope.get(key) { return Some(v); }
        }
        None
    }
    pub fn to_flat_map(&self) -> HashMap<String, String> {
        let mut flat = self.global.clone();
        for scope in self.scoped.values() {
            flat.extend(scope.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        flat
    }
    pub fn merge_from(&mut self, other: &VariableScope) {
        self.global.extend(other.global.clone());
        for (plugin, vars) in &other.scoped {
            self.scoped
                .entry(plugin.clone())
                .or_default()
                .extend(vars.clone());
        }
    }
}

// ─── ScanContext ────────────────────────────────────────────────────────

/// Typed execution context passed to every plugin.
pub struct ScanContext {
    pub target: String,
    pub target_host: String,
    pub template: Arc<crate::template::schema::VulnerabilityTemplate>, // Passed via Arc, no cloning!
    pub variables: Arc<RwLock<VariableScope>>,
    pub finding_tx: mpsc::Sender<FindingOwned>,
    pub cancellation: CancellationToken,
}

impl ScanContext {
    pub async fn snapshot_variables(&self) -> HashMap<String, String> {
        self.variables.read().await.to_flat_map()
    }
    pub async fn set_variable(&self, plugin_name: &str, key: &str, value: String) {
        self.variables.write().await.set(plugin_name, key, value);
    }
    pub async fn emit_finding(&self, finding: FindingOwned) -> Result<(), mpsc::error::SendError<FindingOwned>> {
        self.finding_tx.send(finding).await
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

// ─── PluginOutcome & Metrics ────────────────────────────────────────────

#[derive(Debug)]
pub enum PluginOutcome {
    NoMatch,
    Matched { count: usize },
    Skipped { reason: String },
    Failed { error: crate::core::error::ScannerError, retryable: bool },
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum PluginOutcomeKind {
    /// Plugin found no vulnerabilities.
    #[serde(rename = "no_match")]
    NoMatch,
    /// Plugin found vulnerabilities.
    #[serde(rename = "matched")]
    Matched,
    /// Plugin skipped execution.
    #[serde(rename = "skipped")]
    Skipped,
    /// Plugin execution failed with an error.
    #[serde(rename = "failed")]
    Failed,
    /// Plugin timed out.
    #[serde(rename = "timed_out")]
    TimedOut,
    /// Plugin panicked.
    #[serde(rename = "crashed")]
    Crashed,
}

impl std::fmt::Display for PluginOutcomeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMatch => write!(f, "no_match"),
            Self::Matched => write!(f, "matched"),
            Self::Skipped => write!(f, "skipped"),
            Self::Failed => write!(f, "failed"),
            Self::TimedOut => write!(f, "timed_out"),
            Self::Crashed => write!(f, "crashed"),
        }
    }
}

/// Per-plugin execution metrics collected during a scan.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginMetrics {
    pub plugin_name: String,
    pub target: String,
    pub outcome: PluginOutcomeKind,
    pub duration: Duration,
    pub finding_count: usize,
}

/// Result of a plugin health check.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginHealth {
    pub plugin_name: String,
    pub is_healthy: bool,
    pub error: Option<String>,
    pub last_checked_ms: u64,
}

/// Minimum API version required for plugin compatibility.
/// Plugins declaring a lower version will be rejected at registration.
pub const MINIMUM_API_VERSION: &str = "1.0";

// ─── ScanPlugin Trait (Enterprise Lifecycle) ────────────────────────────

/// A scan plugin with full lifecycle management.
/// No `RefUnwindSafe` bound needed here, handled at the call site.
#[async_trait::async_trait]
pub trait ScanPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str { "0.1.0" }
    fn api_version(&self) -> &str { "1.0" }

    fn is_applicable(&self, template: &crate::template::schema::VulnerabilityTemplate) -> bool;

    /// Validate the plugin's configuration against a template.
    fn validate_config(&self, _template: &crate::template::schema::VulnerabilityTemplate) -> Result<(), crate::core::error::ScannerError> { Ok(()) }
    async fn init(&self) -> Result<(), crate::core::error::ScannerError> { Ok(()) }

    /// Execute the plugin's scan logic.
    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome;

    async fn shutdown(&self) -> Result<(), crate::core::error::ScannerError> { Ok(()) }

    /// Perform a health check. Returns `Ok(())` if healthy, or an error describing
    /// what is wrong. Called by `PluginRegistry::health_check_all()`.
    async fn health_check(&self) -> Result<(), crate::core::error::ScannerError> { Ok(()) }

    fn depends_on(&self) -> &[&'static str] { &[] }
    fn timeout(&self) -> Duration { Duration::from_secs(60) }
}

// ─── Matcher Trait (zero-copy on &[u8]) ─────────────────────────────────

/// Evaluates a response buffer against matching rules.
/// Operates entirely on `&[u8]` byte slices — no allocations in the hot path.
pub trait Matcher: Send + Sync {
    /// Returns `true` if the response matches the vulnerability signature.
    fn evaluate(&self, response_buffer: &[u8]) -> bool;
    /// Human-readable name for diagnostics.
    fn name(&self) -> &str { "unnamed" }
}

// ─── Reporter Trait (async-safe) ────────────────────────────────────────

/// Processes and outputs findings. The Consumer in the MPSC architecture.
///
/// Uses `async_trait` because reporters may need async I/O (file writes,
/// network sends to SIEM). The consumer task calls this from an async context.
#[async_trait::async_trait]
pub trait Reporter: Send + Sync {
    /// Process a single finding.
    async fn process_finding(&self, finding: &FindingOwned) -> Result<(), std::io::Error>;

    /// Flush all buffered output. Called on shutdown.
    async fn flush(&self) -> Result<(), std::io::Error> {
        Ok(())
    }
}
