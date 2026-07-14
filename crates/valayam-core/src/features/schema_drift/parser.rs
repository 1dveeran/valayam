use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SchemaDriftTemplate {
    pub target: String,
    pub openapi_spec: String,
}
