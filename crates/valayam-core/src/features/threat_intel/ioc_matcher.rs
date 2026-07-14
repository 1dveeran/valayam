use std::collections::HashSet;

/// Matches extracted indicators against known threat feeds.
pub struct IocMatcher {
    pub malicious_ips: HashSet<String>,
    pub malicious_domains: HashSet<String>,
}

impl IocMatcher {
    pub fn new() -> Self {
        Self {
            malicious_ips: HashSet::new(),
            malicious_domains: HashSet::new(),
        }
    }
    
    /// Checks if an IP is in the malicious IPs list.
    pub fn is_malicious_ip(&self, ip: &str) -> bool {
        self.malicious_ips.contains(ip)
    }
}
