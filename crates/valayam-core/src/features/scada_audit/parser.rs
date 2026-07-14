use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScadaAuditTemplate {
    pub target: String,
    pub protocol: String, // "modbus", "dnp3"
}
