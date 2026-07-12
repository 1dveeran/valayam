use crate::features::dns_audit::parser::DnsRequestTemplate;
use crate::features::http_scan::parser::HttpRequestTemplate;
use crate::features::network_scan::parser::NetworkRequestTemplate;
use crate::features::scripting::parser::ScriptTemplate;
use crate::features::tls_audit::parser::TlsAuditTemplate;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;

/// Top-level template structure that composes types from all feature slices.
/// This is the single entry point for YAML deserialization of native templates.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnerabilityTemplate {
    pub id: String,
    pub info: TemplateInfo,
    #[serde(default)]
    pub requests: Vec<HttpRequestTemplate>,
    #[serde(default)]
    pub network: Vec<NetworkRequestTemplate>,
    #[serde(default)]
    pub scripts: Vec<ScriptTemplate>,
    #[serde(default)]
    pub dns: Vec<DnsRequestTemplate>,
    #[serde(default)]
    pub tls: Vec<TlsAuditTemplate>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TemplateInfo {
    pub name: String,
    pub severity: String,
    pub description: Option<String>,
}

impl VulnerabilityTemplate {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, crate::core::error::ScannerError> {
        let file = File::open(path)?;
        let template: VulnerabilityTemplate = serde_yaml::from_reader(file)?;
        Ok(template)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_valid_template_parsing() {
        let yaml = r#"
id: test-template
info:
  name: Test
  severity: Info
requests:
  - method: GET
    path: /
    matchers:
      - type: status
        part: status
        status:
          - 200
        "#;
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", yaml).unwrap();

        let template = VulnerabilityTemplate::load(file.path()).unwrap();
        assert_eq!(template.id, "test-template");
        assert_eq!(template.info.name, "Test");
        assert!(!template.requests.is_empty());
    }

    #[test]
    fn test_invalid_template_parsing() {
        let yaml = r#"
id: test-template
info:
  name: Test
  severity: Info
invalid_key: true
        "#;

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", yaml).unwrap();

        let result = VulnerabilityTemplate::load(file.path());
        assert!(result.is_ok(), "Serde ignores unknown fields by default unless specified");
    }

    #[test]
    fn test_template_with_extractors() {
        let yaml = r#"
id: extractor-test
info:
  name: Extractor Demo
  severity: Medium
requests:
  - method: POST
    path: /login
    body: "username=admin&password=admin"
    extractors:
      - type: regex
        name: auth_token
        part: body
        regex: '"token":\s*"([^"]+)"'
        group: 1
    matchers:
      - type: status
        part: status
        status:
          - 200
  - method: GET
    path: /api/data
    headers:
      Authorization: "Bearer {{auth_token}}"
    matchers:
      - type: regex
        part: body
        regex:
          - "sensitive_data"
        "#;
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", yaml).unwrap();

        let template = VulnerabilityTemplate::load(file.path()).unwrap();
        assert_eq!(template.requests.len(), 2);
        assert!(!template.requests[0].extractors.is_empty());
        assert_eq!(template.requests[0].extractors[0].name, "auth_token");
    }

    #[test]
    fn test_template_with_dns_and_tls() {
        let yaml = r#"
id: dns-tls-test
info:
  name: DNS and TLS Test
  severity: Info
dns:
  - domain: "{{Hostname}}"
    query_type: CNAME
    matchers:
      - type: regex
        part: body
        regex:
          - "cloudfront\\.net"
tls:
  - host: "{{Hostname}}"
    port: 443
    matchers:
      - type: expired
        part: body
        "#;
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", yaml).unwrap();

        let template = VulnerabilityTemplate::load(file.path()).unwrap();
        assert!(!template.dns.is_empty());
        assert!(!template.tls.is_empty());
    }
}
