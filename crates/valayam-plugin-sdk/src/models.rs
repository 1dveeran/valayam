use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct WasmInput {
    pub template: serde_json::Value,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub template_id: String,
    pub template_name: String,
    pub severity: String,
    pub target: String,
    pub matched_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solution: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extracted_data: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WasmOutput {
    pub matched: bool,
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

pub trait WasmScanner {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error>;
}
