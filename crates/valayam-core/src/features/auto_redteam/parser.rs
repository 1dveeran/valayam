use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AutoRedteamTemplate {
    pub target: String,
    pub objective: String,
}
