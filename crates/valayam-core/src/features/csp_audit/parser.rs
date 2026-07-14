use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CspAuditTemplate {
    pub target: String,
    pub strict_mode: bool,
}
