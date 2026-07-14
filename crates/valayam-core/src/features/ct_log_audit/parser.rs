use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CtLogAuditTemplate {
    pub target: String,
    pub query_domain: String,
}
