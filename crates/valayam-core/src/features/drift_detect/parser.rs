use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DriftDetectTemplate {
    pub target: String,
    pub storage_backend: Option<String>, // "local", "redis"
    pub baseline_id: String,
}
