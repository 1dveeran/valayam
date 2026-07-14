use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CorsAuditTemplate {
    pub target: String,
    pub origins_to_test: Option<Vec<String>>,
}
