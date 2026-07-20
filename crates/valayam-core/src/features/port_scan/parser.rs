use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortScanTemplate {
    #[serde(default)]
    pub target: Option<String>,
    pub ports: Vec<u16>,
}
