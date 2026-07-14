use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortScanTemplate {
    pub target: String,
    pub ports: Vec<u16>,
}
