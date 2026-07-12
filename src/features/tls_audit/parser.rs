use crate::core::matcher::ResponseMatcher;
use serde::{Deserialize, Serialize};

/// Defines a TLS/SSL certificate audit step within a native template.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TlsAuditTemplate {
    pub host: String,
    #[serde(default = "default_tls_port")]
    pub port: u16,
    #[serde(default)]
    pub matchers: Vec<ResponseMatcher>,
}

fn default_tls_port() -> u16 {
    443
}
