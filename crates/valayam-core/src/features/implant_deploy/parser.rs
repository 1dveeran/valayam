use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImplantDeployTemplate {
    pub target: String,
    pub payload_name: String,
}
