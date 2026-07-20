use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web3AuditTemplate {
    pub rpc_endpoint: Option<String>,
    pub bytecode: Option<String>,
    pub action: String, // "fuzz_rpc" or "static_analyze"
}
