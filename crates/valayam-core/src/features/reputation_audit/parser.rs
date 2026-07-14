use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReputationAuditTemplate {
    pub target: String,
    pub blocklists: Vec<String>,
}
