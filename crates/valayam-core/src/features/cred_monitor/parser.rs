use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredMonitorTemplate {
    pub target_domain: String,
    pub emails: Vec<String>,
}
