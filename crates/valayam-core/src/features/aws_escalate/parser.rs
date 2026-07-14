use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AwsEscalateTemplate {
    pub target: String,
    pub region: Option<String>,
}
