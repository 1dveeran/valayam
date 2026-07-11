use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NucleiTemplate {
    pub id: String,
    pub info: NucleiTemplateInfo,
    #[serde(default)]
    pub requests: Vec<NucleiRequestTemplate>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NucleiTemplateInfo {
    pub name: String,
    pub author: Option<String>,
    pub severity: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NucleiRequestTemplate {
    pub method: String,
    pub path: Vec<String>,
    #[serde(default)]
    pub headers: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "matchers-condition", default = "default_matchers_condition")]
    pub matchers_condition: String,
    pub matchers: Vec<NucleiMatcher>,
}

fn default_matchers_condition() -> String {
    "or".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NucleiMatcher {
    pub r#type: String, // "word", "status", etc.
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub status: Option<Vec<u16>>,
    #[serde(default = "default_matcher_part")]
    pub part: String,
}

fn default_matcher_part() -> String {
    "body".to_string()
}

impl NucleiTemplate {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, crate::core::error::ScannerError> {
        let file = File::open(path)?;
        let template: NucleiTemplate = serde_yaml::from_reader(file)?;
        Ok(template)
    }
}
