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
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solution: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extracted_data: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl FindingOwned {
    /// Produces a deduplication key from the triple `(template_id, target, matched_at)`.
    /// Two findings with the same key are considered duplicates.
    #[must_use]
    pub fn dedup_key(&self) -> (String, String, String) {
        (
            self.template_id.clone(),
            self.target.clone(),
            self.matched_at.clone(),
        )
    }

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
    pub async fn emit_finding(&self, mut finding: FindingOwned) -> Result<(), mpsc::error::SendError<FindingOwned>> {
        // Auto-inject description if the plugin omitted it
        if finding.description.is_none() {
            finding.description = self.template.info.description.clone();
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── FindingOwned tests ─────────────────────────────────────────────────

    #[test]
    fn test_finding_owned_dedup_key() {
        let f = FindingOwned {
            template_id: "test-001".into(),
            template_name: "Test Finding".into(),
            severity: "high".into(),
            target: "https://example.com".into(),
            matched_at: "/login".into(),
            description: None,
            solution: None,
            extracted_data: None,
            metadata: Default::default(),
        };
        let key = f.dedup_key();
        assert_eq!(key, ("test-001".into(), "https://example.com".into(), "/login".into()));
    }

    #[test]
    fn test_finding_owned_dedup_key_differentiates() {
        let f1 = FindingOwned {
            template_id: "test-001".into(),
            target: "https://example.com".into(),
            matched_at: "/login".into(),
            ..default_finding()
        };
        let f2 = FindingOwned {
            template_id: "test-002".into(),
            target: "https://example.com".into(),
            matched_at: "/login".into(),
            ..default_finding()
        };
        let f3 = FindingOwned {
            template_id: "test-001".into(),
            target: "https://other.com".into(),
            matched_at: "/login".into(),
            ..default_finding()
        };
        assert_ne!(f1.dedup_key(), f2.dedup_key());
        assert_ne!(f1.dedup_key(), f3.dedup_key());
    }

    #[test]
    fn test_finding_owned_into_scan_result() {
        let f = FindingOwned {
            template_id: "cve-2024-1234".into(),
            template_name: "SQL Injection Test".into(),
            severity: "critical".into(),
            target: "https://target.com/login".into(),
            matched_at: "error in SQL parser".into(),
            description: Some("SQLi detected".into()),
            solution: Some("Use prepared statements".into()),
            extracted_data: Some("admin' OR 1=1".into()),
            metadata: [("cwe".into(), "89".into())].into(),
        };

        let sr = f.into_scan_result();
        assert_eq!(sr.template_id, "cve-2024-1234");
        assert_eq!(sr.template_name, "SQL Injection Test");
        assert_eq!(sr.template_severity, "critical");
        assert_eq!(sr.target, "https://target.com/login");
        assert_eq!(sr.payload, "error in SQL parser");
    }

    // ── VariableScope tests ────────────────────────────────────────────────

    #[test]
    fn test_variable_scope_new() {
        let mut globals = HashMap::new();
        globals.insert("BaseURL".into(), "https://example.com".into());
        let scope = VariableScope::new(globals);
        assert_eq!(scope.get("BaseURL").unwrap(), "https://example.com");
        assert!(scope.get("missing").is_none());
    }

    #[test]
    fn test_variable_scope_set_global() {
        let mut scope = VariableScope::new(HashMap::new());
        scope.set_global("Hostname", "example.com");
        assert_eq!(scope.get("Hostname").unwrap(), "example.com");
    }

    #[test]
    fn test_variable_scope_set_scoped() {
        let mut scope = VariableScope::new(HashMap::new());
        scope.set("http_plugin", "response_body", "data");
        assert_eq!(scope.get("response_body").unwrap(), "data");
    }

    #[test]
    fn test_variable_scope_global_takes_precedence() {
        let mut scope = VariableScope::new(HashMap::new());
        scope.set_global("key", "global_val");
        scope.set("plugin_a", "key", "scoped_val");
        // Global takes priority since it's checked first
        assert_eq!(scope.get("key").unwrap(), "global_val");
    }

    #[test]
    fn test_variable_scope_scoped_isolation() {
        let mut scope = VariableScope::new(HashMap::new());
        scope.set("plugin_a", "key_a", "value_a");
        scope.set("plugin_b", "key_b", "value_b");
        // Each key only exists in one scope, so get() returns the correct value
        // regardless of HashMap iteration order
        assert_eq!(scope.get("key_a").unwrap(), "value_a");
        assert_eq!(scope.get("key_b").unwrap(), "value_b");
    }

    #[test]
    fn test_variable_scope_to_flat_map() {
        let mut scope = VariableScope::new(HashMap::new());
        scope.set_global("g1", "global1");
        scope.set("p1", "s1", "scoped1");
        let flat = scope.to_flat_map();
        assert_eq!(flat.get("g1").unwrap(), "global1");
        assert_eq!(flat.get("s1").unwrap(), "scoped1");
    }

    #[test]
    fn test_variable_scope_merge_from() {
        let mut scope_a = VariableScope::new(HashMap::new());
        scope_a.set_global("key_a", "val_a");
        scope_a.set("p1", "key_b", "val_b");

        let mut scope_b = VariableScope::new(HashMap::new());
        scope_b.set_global("key_c", "val_c");
        scope_b.set("p1", "key_d", "val_d");

        scope_a.merge_from(&scope_b);
        assert_eq!(scope_a.get("key_a").unwrap(), "val_a");
        assert_eq!(scope_a.get("key_c").unwrap(), "val_c");
        assert_eq!(scope_a.get("key_d").unwrap(), "val_d");
    }

    #[test]
    fn test_variable_scope_merge_overwrites_global() {
        let mut scope_a = VariableScope::new(HashMap::new());
        scope_a.set_global("key", "old");

        let mut scope_b = VariableScope::new(HashMap::new());
        scope_b.set_global("key", "new");

        scope_a.merge_from(&scope_b);
        assert_eq!(scope_a.get("key").unwrap(), "new");
    }

    // ── ScanContext tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_scan_context_snapshot_variables() {
        let vars = Arc::new(RwLock::new(VariableScope::new({
            let mut m = HashMap::new();
            m.insert("BaseURL".into(), "https://example.com".into());
            m
        })));

        let ctx = ScanContext {
            target: "https://example.com".into(),
            target_host: "example.com".into(),
            template: Arc::new(crate::template::schema::VulnerabilityTemplate::default()),
            variables: vars,
            finding_tx: mpsc::channel(10).0,
            cancellation: CancellationToken::new(),
        };

        let snapshot = ctx.snapshot_variables().await;
        assert_eq!(snapshot.get("BaseURL").unwrap(), "https://example.com");
    }

    #[tokio::test]
    async fn test_scan_context_set_variable() {
        let vars = Arc::new(RwLock::new(VariableScope::new(HashMap::new())));
        let ctx = ScanContext {
            target: "https://example.com".into(),
            target_host: "example.com".into(),
            template: Arc::new(crate::template::schema::VulnerabilityTemplate::default()),
            variables: vars.clone(),
            finding_tx: mpsc::channel(10).0,
            cancellation: CancellationToken::new(),
        };

        ctx.set_variable("test_plugin", "extracted", "secret_value".to_string()).await;
        let snapshot = ctx.snapshot_variables().await;
        assert_eq!(snapshot.get("extracted").unwrap(), "secret_value");
    }

    #[tokio::test]
    async fn test_scan_context_is_cancelled() {
        let token = CancellationToken::new();
        let ctx = ScanContext {
            target: "https://example.com".into(),
            target_host: "example.com".into(),
            template: Arc::new(crate::template::schema::VulnerabilityTemplate::default()),
            variables: Arc::new(RwLock::new(VariableScope::new(HashMap::new()))),
            finding_tx: mpsc::channel(10).0,
            cancellation: token.clone(),
        };
        assert!(!ctx.is_cancelled());
        token.cancel();
        assert!(ctx.is_cancelled());
    }

    #[tokio::test]
    async fn test_scan_context_emit_finding() {
        let (tx, mut rx) = mpsc::channel(10);
        let ctx = ScanContext {
            target: "https://example.com".into(),
            target_host: "example.com".into(),
            template: Arc::new(crate::template::schema::VulnerabilityTemplate {
                id: "test".into(),
                info: crate::template::schema::TemplateInfo {
                    name: "Test".into(),
                    severity: "info".into(),
                    description: Some("desc".into()),
                    compliance: Default::default(),
                },
                ..crate::template::schema::VulnerabilityTemplate::default()
            }),
            variables: Arc::new(RwLock::new(VariableScope::new(HashMap::new()))),
            finding_tx: tx,
            cancellation: CancellationToken::new(),
        };

        let finding = FindingOwned {
            template_id: "test-001".into(),
            template_name: "Test".into(),
            severity: "info".into(),
            target: "https://example.com".into(),
            matched_at: "matched".into(),
            description: None, // Should be auto-injected
            solution: None,
            extracted_data: None,
            metadata: Default::default(),
        };

        ctx.emit_finding(finding).await.unwrap();
        let received = rx.recv().await.unwrap();
        assert_eq!(received.template_id, "test-001");
        // Description should be auto-injected from template
        assert_eq!(received.description.unwrap(), "desc");
    }

    // ── PluginOutcomeKind tests ────────────────────────────────────────────

    #[test]
    fn test_plugin_outcome_kind_display() {
        assert_eq!(PluginOutcomeKind::NoMatch.to_string(), "no_match");
        assert_eq!(PluginOutcomeKind::Matched.to_string(), "matched");
        assert_eq!(PluginOutcomeKind::Skipped.to_string(), "skipped");
        assert_eq!(PluginOutcomeKind::Failed.to_string(), "failed");
        assert_eq!(PluginOutcomeKind::TimedOut.to_string(), "timed_out");
        assert_eq!(PluginOutcomeKind::Crashed.to_string(), "crashed");
    }

    #[test]
    fn test_plugin_outcome_kind_serde_round_trip() {
        let cases = vec![
            PluginOutcomeKind::NoMatch,
            PluginOutcomeKind::Matched,
            PluginOutcomeKind::Failed,
            PluginOutcomeKind::Crashed,
        ];
        for kind in cases {
            let json = serde_json::to_string(&kind).unwrap();
            let back: PluginOutcomeKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    // ── PluginMetrics tests ────────────────────────────────────────────────

    #[test]
    fn test_plugin_metrics_serde() {
        let m = PluginMetrics {
            plugin_name: "http_scan".into(),
            target: "https://example.com".into(),
            outcome: PluginOutcomeKind::Matched,
            duration: Duration::from_millis(150),
            finding_count: 3,
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: PluginMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(back.plugin_name, "http_scan");
        assert_eq!(back.outcome, PluginOutcomeKind::Matched);
        assert_eq!(back.finding_count, 3);
        assert_eq!(back.duration.as_millis(), 150);
    }

    // ── PluginHealth tests ─────────────────────────────────────────────────

    #[test]
    fn test_plugin_health_healthy() {
        let h = PluginHealth {
            plugin_name: "test_plugin".into(),
            is_healthy: true,
            error: None,
            last_checked_ms: 42,
        };
        assert!(h.is_healthy);
        assert!(h.error.is_none());
    }

    #[test]
    fn test_plugin_health_unhealthy() {
        let h = PluginHealth {
            plugin_name: "broken_plugin".into(),
            is_healthy: false,
            error: Some("out of memory".into()),
            last_checked_ms: 7,
        };
        assert!(!h.is_healthy);
        assert_eq!(h.error.unwrap(), "out of memory");
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    fn default_finding() -> FindingOwned {
        FindingOwned {
            template_id: String::new(),
            template_name: String::new(),
            severity: String::new(),
            target: String::new(),
            matched_at: String::new(),
            description: None,
            solution: None,
            extracted_data: None,
            metadata: HashMap::new(),
        }
    }
}
