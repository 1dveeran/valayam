use serde::{Deserialize, Serialize};

/// Shared matcher type used across multiple feature slices.
/// Supports regex matching against response bodies/headers and HTTP status code matching.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseMatcher {
    pub r#type: String, // e.g., "regex" or "status"
    pub part: String,   // e.g., "body", "header", "status", "banner"
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub status: Option<Vec<u16>>,
}
