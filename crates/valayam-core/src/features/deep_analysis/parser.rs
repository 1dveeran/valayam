use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeepAnalysisTemplate {
    pub target: String,
    pub analysis_type: String, // "llm_mutation", "wasm_decompile", "source_map", "artifact_recovery"
    pub prompt: Option<String>,
}
