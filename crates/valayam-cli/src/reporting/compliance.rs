use std::collections::HashMap;

/// Maps vulnerabilities to standard compliance frameworks.
pub struct ComplianceMapper;

impl ComplianceMapper {
    /// Maps a given template tag (e.g., "sqli", "xss") to OWASP Top 10 and CWE.
    pub fn get_compliance_info(tags: &[String]) -> HashMap<&'static str, &'static str> {
        let mut info = HashMap::new();
        
        for tag in tags {
            match tag.as_str() {
                "sqli" => {
                    info.insert("OWASP", "A03:2021-Injection");
                    info.insert("CWE", "CWE-89");
                },
                "xss" => {
                    info.insert("OWASP", "A03:2021-Injection");
                    info.insert("CWE", "CWE-79");
                },
                _ => {}
            }
        }
        
        info
    }
}
