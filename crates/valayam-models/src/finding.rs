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
    /// Construct a FindingOwned from a metadata HashMap.
    ///
    /// The metadata HashMap should contain:
    /// - `template_id`, `template_name`, `template_severity` — extracted to proper fields
    /// - `cvss_score`, `solution`, `reference`, `tags` — stored with `::` prefix in metadata
    /// - Everything else (compliance data, etc.) — stored verbatim in metadata
    pub fn from_template(
        target: impl Into<String>,
        matched_at: impl Into<String>,
        metadata: std::collections::HashMap<String, String>,
    ) -> Self {
        let target = target.into();
        let matched_at = matched_at.into();

        let template_id = metadata.get("template_id").cloned().unwrap_or_default();
        let template_name = metadata.get("template_name").cloned().unwrap_or_default();
        let severity = metadata.get("template_severity").cloned().unwrap_or_default();

        let mut meta = std::collections::HashMap::new();
        for (key, value) in metadata {
            match key.as_str() {
                "template_id" | "template_name" | "template_severity" => {
                    // Already extracted as proper fields above
                }
                "cvss_score" => {
                    meta.insert("::cvss_score".to_string(), value);
                }
                "solution" => {
                    meta.insert("::solution".to_string(), value);
                }
                "reference" => {
                    meta.insert("::reference".to_string(), value);
                }
                "tags" => {
                    meta.insert("::tags".to_string(), value);
                }
                other => {
                    meta.insert(other.to_string(), value);
                }
            }
        }

        Self {
            template_id,
            template_name,
            severity,
            target,
            matched_at,
            description: None,
            solution: None,
            extracted_data: None,
            metadata: meta,
        }
    }

    /// Convenience constructor for executors that have template metadata.
    /// Compliance data from the template is automatically included in metadata.
    /// Use this when no extra fields (cvss, solution, etc.) are needed.
    pub fn from_template_and_info(
        template_id: impl Into<String>,
        template_meta: &dyn crate::template_info::TemplateMetadata,
        target: impl Into<String>,
        matched_at: impl Into<String>,
    ) -> Self {
        Self {
            template_id: template_id.into(),
            template_name: template_meta.template_name().to_string(),
            severity: template_meta.template_severity().to_string(),
            target: target.into(),
            matched_at: matched_at.into(),
            description: template_meta.description().map(|s| s.to_string()),
            solution: None,
            extracted_data: None,
            metadata: template_meta.compliance().clone(),
        }
    }

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
