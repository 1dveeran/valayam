use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CicdAuditTemplate {
    pub target_repo: String,
}
