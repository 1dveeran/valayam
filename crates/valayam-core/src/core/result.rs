use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents a single, confirmed vulnerability finding.
/// This structure is serialized to JSON for structured logging.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
    pub template_id: String,
    pub template_name: String,
    pub template_severity: String,
    pub target: String,
    pub payload: String,
}
