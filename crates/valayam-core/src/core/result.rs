// TODO: Expand ScanResult for Compliance & Reporting.
// - Add `compliance` mapping fields (e.g. OWASP, MITRE ATT&CK).
// - Support multiple output formats natively (JSON, SARIF).
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents a single, confirmed vulnerability finding.
/// This structure is serialized to JSON for structured logging.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanResult {
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
    pub template_id: String,
    pub template_name: String,
    pub template_severity: String,
    pub target: String,
    pub payload: String,
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub compliance: std::collections::HashMap<String, String>,
}
