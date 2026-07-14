use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloudTemplate {
    pub provider: String,
    pub action: String,
}
