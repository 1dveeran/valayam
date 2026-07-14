use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyAuditTemplate {
    pub target_repo: String,
}
