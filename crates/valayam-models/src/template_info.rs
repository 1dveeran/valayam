use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TemplateInfo {
    pub name: String,
    pub severity: String,
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub compliance: HashMap<String, String>,
}
