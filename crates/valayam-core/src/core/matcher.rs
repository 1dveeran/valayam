use serde::{Deserialize, Serialize};

/// Shared matcher type used across multiple feature slices.
/// Supports regex matching against response bodies/headers, word matching, and HTTP status code matching.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseMatcher {
    pub r#type: String, // e.g., "regex", "status", "word"
    pub part: String,   // e.g., "body", "header", "status", "banner"
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub status: Option<Vec<u16>>,
    #[serde(default)]
    pub negative: bool,
    #[serde(default = "default_condition")]
    pub condition: String,
}

fn default_condition() -> String {
    "and".to_string()
}
