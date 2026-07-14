use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MitreMappingTemplate {
    pub enable_mapping: bool,
}
