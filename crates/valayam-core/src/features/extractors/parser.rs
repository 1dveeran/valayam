use serde::{Deserialize, Serialize};

/// Defines a value extraction rule that captures data from HTTP responses.
///
/// When a regex matches against the specified response part (body or header),
/// the engine captures the specified group and stores it as a named variable
/// accessible via `{{name}}` in subsequent requests.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Extractor {
    /// Extraction type. Currently supports "regex".
    pub r#type: String,

    /// Variable name for the extracted value (e.g., "auth_token").
    /// Available as `{{auth_token}}` in subsequent requests.
    pub name: String,

    /// Response part to extract from: "body" or "header".
    #[serde(default = "default_part")]
    pub part: String,

    /// Regex pattern with capture groups. The `group` index selects which
    /// capture group to extract.
    #[serde(default)]
    pub regex: Option<String>,

    /// Capture group index to extract (default: 1 = first group).
    #[serde(default = "default_group")]
    pub group: usize,
}

fn default_part() -> String {
    "body".to_string()
}

fn default_group() -> usize {
    1
}
