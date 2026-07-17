use serde::{Deserialize, Serialize};

fn default_sensitivity() -> String {
    "medium".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DriftDetectTemplate {
    pub target: String,
    pub storage_backend: Option<String>, // "local", "redis"
    pub baseline_id: String,
    /// Drift sensitivity level: "low", "medium" (default), or "high"
    /// - low:   status code and endpoint changes only
    /// - medium: status + body hash changes
    /// - high:  status + body hash + header structure changes
    #[serde(default = "default_sensitivity")]
    pub sensitivity: String,
}
