use serde::{Deserialize, Serialize};

/// Defines a scripted scan step. The `engine` field is future-proofed
/// for additional scripting runtimes (e.g., "lua") beyond "rhai".
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScriptTemplate {
    pub engine: String,
    pub source: ScriptSource,
}

/// Supports two deserialization shapes via `#[serde(untagged)]`:
/// - Inline: `{ code: "..." }`
/// - File:   `{ path: "./scripts/foo.rhai" }`
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ScriptSource {
    Inline { code: String },
    File { path: String },
}
