use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DomRedirectAuditTemplate {
    pub target: String,
    pub parameters: Vec<String>,
}
