use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct K8sAuditTemplate {
    pub target_manifest: String,
    pub strict_rbac: bool,
}
