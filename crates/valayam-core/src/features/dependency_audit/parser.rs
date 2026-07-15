use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyAuditTemplate {
    pub target_repo: String,
    pub cve_mode: Option<String>,
    pub api_url: Option<String>,
    pub local_db_path: Option<String>,
}
