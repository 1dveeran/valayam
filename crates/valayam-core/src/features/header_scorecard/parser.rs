use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeaderScorecardTemplate {
    pub target: String,
    pub required_headers: Vec<String>,
}
