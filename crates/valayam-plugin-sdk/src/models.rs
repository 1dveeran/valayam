use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Error type: real extism_pdk::Error on wasm32, stub on host builds.
#[cfg(target_arch = "wasm32")]
pub type PluginError = extism_pdk::Error;
#[cfg(not(target_arch = "wasm32"))]
pub type PluginError = Box<dyn std::error::Error + Send + Sync>;

// Result type matching extism_pdk::FnResult on wasm32.
#[cfg(target_arch = "wasm32")]
pub type PluginResult<T> = extism_pdk::FnResult<T>;
#[cfg(not(target_arch = "wasm32"))]
pub type PluginResult<T> = Result<T, PluginError>;

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
    fn scan(&self, input: WasmInput) -> PluginResult<WasmOutput>;
}