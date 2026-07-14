use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GrpcAuditTemplate {
    pub target: String,
    pub service: Option<String>,
    pub method: Option<String>,
    pub reflection: bool,
}
