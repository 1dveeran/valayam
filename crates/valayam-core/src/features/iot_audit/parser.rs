use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IotAuditTemplate {
    pub target: String,
    pub protocol: String, // "mqtt", "coap"
    pub topics: Option<Vec<String>>,
}
