use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RemediationGenTemplate {
    pub output_format: String, // "markdown", "json", "pdf"
}
