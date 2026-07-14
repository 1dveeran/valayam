use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WafBypassVerifyTemplate {
    pub target: String,
    pub payloads: Vec<String>,
}
