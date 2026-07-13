use crate::core::matcher::ResponseMatcher;
use serde::{Deserialize, Serialize};

/// Defines a network (TCP/UDP) scan step within a native template.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkRequestTemplate {
    pub host: String,
    pub ports: Vec<String>,
    /// Timeout in milliseconds for banner grabbing. If set, the scanner will
    /// attempt to read initial bytes from each open TCP port.
    #[serde(default)]
    pub banner_timeout_ms: Option<u64>,
    /// Protocol to use: "tcp" (default) or "udp".
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub matchers: Vec<ResponseMatcher>,
}

fn default_protocol() -> String {
    "tcp".to_string()
}
