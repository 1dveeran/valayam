use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use crate::result::ScanResult;

/// A vulnerability finding ready for channel transport and serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub fn into_scan_result(self) -> ScanResult {
        ScanResult {
            schema_version: crate::result::default_schema_version(),
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetrics {
    pub plugin_name: String,
    pub target: String,
    pub outcome: PluginOutcomeKind,
    pub duration: Duration,
    pub finding_count: usize,
}

/// Result of a plugin health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginHealth {
    pub plugin_name: String,
    pub is_healthy: bool,
    pub error: Option<String>,
    pub last_checked_ms: u64,
}
