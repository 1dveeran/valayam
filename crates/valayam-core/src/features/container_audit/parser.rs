use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContainerAuditTemplate {
    pub target_image: String,
    pub checks: Vec<String>,
}
