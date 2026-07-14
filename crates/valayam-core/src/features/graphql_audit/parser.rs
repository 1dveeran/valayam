use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GraphqlAuditTemplate {
    pub target: String,
    pub introspection: bool,
    pub mutate: bool,
}
