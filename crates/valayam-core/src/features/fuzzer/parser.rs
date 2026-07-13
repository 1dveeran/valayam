use serde::{Deserialize, Serialize};
use crate::core::matcher::ResponseMatcher;

/// Defines configuration schema for parameter fuzzing targets.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FuzzTemplate {
    pub part: String,           // e.g., "query", "body", "headers"
    #[serde(default)]
    pub keys: Vec<String>,      // Parameter names to target; if empty, fuzzes all detected keys.
    pub payloads: Vec<String>,  // Payloads to inject
    #[serde(default)]
    pub matchers: Vec<ResponseMatcher>,
}
