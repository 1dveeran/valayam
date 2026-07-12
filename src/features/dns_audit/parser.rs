use crate::core::matcher::ResponseMatcher;
use serde::{Deserialize, Serialize};

/// Defines a DNS query audit step within a native template.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsRequestTemplate {
    pub domain: String,
    /// DNS record type: "A", "AAAA", "CNAME", "TXT", "MX".
    pub query_type: String,
    #[serde(default)]
    pub matchers: Vec<ResponseMatcher>,
}
