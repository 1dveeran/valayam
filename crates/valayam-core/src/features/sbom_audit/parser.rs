use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomAuditTemplate {
    pub target: String,
    pub r#type: String, // "package.json", "Cargo.toml", "requirements.txt"
}
