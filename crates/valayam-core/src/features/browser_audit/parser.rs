use serde::{Deserialize, Serialize};
use crate::core::matcher::ResponseMatcher;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BrowserAuditTemplate {
    pub target: String,
    pub script: String, // Python worker script identifier
    pub matchers: Vec<ResponseMatcher>,
}
