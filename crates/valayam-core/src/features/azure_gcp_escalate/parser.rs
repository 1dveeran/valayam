use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AzureGcpEscalateTemplate {
    pub target: String,
    pub provider: String, // "azure", "gcp"
}
