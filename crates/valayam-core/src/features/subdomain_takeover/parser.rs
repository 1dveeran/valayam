use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SubdomainTakeoverTemplate {
    pub target: String,
}
