use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SastTaintTemplate {
    pub target_dir: String,
    pub language: String,
}
