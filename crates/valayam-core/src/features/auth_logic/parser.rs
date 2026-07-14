use serde::{Deserialize, Serialize};
use crate::core::matcher::ResponseMatcher;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AuthTemplate {
    pub primary: String,
    pub secondary: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogicTemplate {
    pub r#type: String, // E.g., "idor"
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub matchers: Vec<ResponseMatcher>,
}
