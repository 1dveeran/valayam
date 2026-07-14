use serde::{Deserialize, Serialize};
use crate::core::matcher::ResponseMatcher;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IacAuditTemplate {
    pub target: String,
    pub r#type: String, // "terraform", "kubernetes", "docker"
    pub matchers: Vec<ResponseMatcher>,
}
