use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct EasmTemplate {
    /// List of OSINT sources to query, e.g. ["crtsh", "alienvault"]
    pub sources: Vec<String>,
    
    /// Target domain to enumerate subdomains for. Usually "{{Hostname}}" or a literal domain.
    pub domain: String,

    #[serde(default = "default_max_results")]
    pub max_results: usize,
}

fn default_max_results() -> usize {
    1000
}
