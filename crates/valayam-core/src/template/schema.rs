// TODO: Finalize VulnerabilityTemplate schema.
// - Implement strict field validation and linting on load.
// - Expand schema to support Phase 10+ modules (e.g. Crawler, WAF detection).
use crate::features::dns_audit::parser::DnsRequestTemplate;
use crate::features::http_scan::parser::HttpRequestTemplate;
use crate::features::network_scan::parser::NetworkRequestTemplate;
use crate::features::scripting::parser::ScriptTemplate;
use crate::features::tls_audit::parser::TlsAuditTemplate;
use crate::features::fuzzer::parser::FuzzTemplate;
use crate::features::auth_logic::parser::{AuthTemplate, LogicTemplate};
use crate::features::cloud_sec::parser::CloudTemplate;
use crate::features::deep_analysis::parser::DeepAnalysisTemplate;
use crate::features::iac_audit::parser::IacAuditTemplate;
use crate::features::sbom_audit::parser::SbomAuditTemplate;
use crate::features::grpc_audit::parser::GrpcAuditTemplate;
use crate::features::graphql_audit::parser::GraphqlAuditTemplate;
use crate::features::drift_detect::parser::DriftDetectTemplate;
use crate::features::cred_monitor::parser::CredMonitorTemplate;
use crate::features::oauth_audit::parser::OauthAuditTemplate;
use crate::features::idp_audit::parser::IdpAuditTemplate;
use crate::features::aws_escalate::parser::AwsEscalateTemplate;
use crate::features::azure_gcp_escalate::parser::AzureGcpEscalateTemplate;
use crate::features::browser_audit::parser::BrowserAuditTemplate;
use crate::features::iot_audit::parser::IotAuditTemplate;
use crate::features::scada_audit::parser::ScadaAuditTemplate;
use crate::features::auto_redteam::parser::AutoRedteamTemplate;
use crate::features::implant_deploy::parser::ImplantDeployTemplate;
use crate::features::client_secret_audit::parser::ClientSecretAuditTemplate;
use crate::features::dom_redirect_audit::parser::DomRedirectAuditTemplate;
use crate::features::cors_audit::parser::CorsAuditTemplate;
use crate::features::csp_audit::parser::CspAuditTemplate;
use crate::features::waf_bypass_verify::parser::WafBypassVerifyTemplate;
use crate::features::header_scorecard::parser::HeaderScorecardTemplate;
use crate::features::reputation_audit::parser::ReputationAuditTemplate;
use crate::features::ct_log_audit::parser::CtLogAuditTemplate;
use crate::features::remediation_gen::parser::RemediationGenTemplate;
use crate::features::mitre_mapping::parser::MitreMappingTemplate;
use crate::features::container_audit::parser::ContainerAuditTemplate;
use crate::features::k8s_audit::parser::K8sAuditTemplate;
use crate::features::sast_taint::parser::SastTaintTemplate;
use crate::features::sast_secrets::parser::SastSecretsTemplate;
use crate::features::subdomain_takeover::parser::SubdomainTakeoverTemplate;
use crate::features::port_scan::parser::PortScanTemplate;
use crate::features::schema_drift::parser::SchemaDriftTemplate;
use crate::features::pii_leak_audit::parser::PiiLeakAuditTemplate;
use crate::features::auto_exploit::parser::AutoExploitTemplate;
use crate::features::ui_proxy::parser::UiProxyTemplate;
use crate::features::cicd_audit::parser::CicdAuditTemplate;
use crate::features::dependency_audit::parser::DependencyAuditTemplate;
use crate::features::easm::parser::EasmTemplate;
use crate::features::mobile_audit::parser::MobileAuditTemplate;
use crate::features::serverless_audit::parser::ServerlessAuditTemplate;
use crate::features::web3_audit::parser::Web3AuditTemplate;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level template structure that composes types from all feature slices.
/// This is the single entry point for YAML deserialization of native templates.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct VulnerabilityTemplate {
    pub id: String,
    pub info: TemplateInfo,
    #[serde(default)]
    pub auth: Option<AuthTemplate>,
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
    #[serde(default)]
    pub fuzz: Vec<FuzzTemplate>,
    #[serde(default)]
    pub cloud: Vec<CloudTemplate>,
    #[serde(default)]
    pub logic: Vec<LogicTemplate>,
    #[serde(default)]
    pub deep_analysis: Vec<DeepAnalysisTemplate>,
    #[serde(default)]
    pub iac_audit: Vec<IacAuditTemplate>,
    #[serde(default)]
    pub sbom_audit: Vec<SbomAuditTemplate>,
    #[serde(default)]
    pub grpc_audit: Vec<GrpcAuditTemplate>,
    #[serde(default)]
    pub graphql_audit: Vec<GraphqlAuditTemplate>,
    #[serde(default)]
    pub drift_detect: Vec<DriftDetectTemplate>,
    #[serde(default)]
    pub cred_monitor: Vec<CredMonitorTemplate>,
    #[serde(default)]
    pub oauth_audit: Vec<OauthAuditTemplate>,
    #[serde(default)]
    pub idp_audit: Vec<IdpAuditTemplate>,
    #[serde(default)]
    pub aws_escalate: Vec<AwsEscalateTemplate>,
    #[serde(default)]
    pub azure_gcp_escalate: Vec<AzureGcpEscalateTemplate>,
    #[serde(default)]
    pub browser_audit: Vec<BrowserAuditTemplate>,
    #[serde(default)]
    pub iot_audit: Vec<IotAuditTemplate>,
    #[serde(default)]
    pub scada_audit: Vec<ScadaAuditTemplate>,
    #[serde(default)]
    pub auto_redteam: Vec<AutoRedteamTemplate>,
    #[serde(default)]
    pub implant_deploy: Vec<ImplantDeployTemplate>,
    #[serde(default)]
    pub client_secret_audit: Vec<ClientSecretAuditTemplate>,
    #[serde(default)]
    pub dom_redirect_audit: Vec<DomRedirectAuditTemplate>,
    #[serde(default)]
    pub cors_audit: Vec<CorsAuditTemplate>,
    #[serde(default)]
    pub csp_audit: Vec<CspAuditTemplate>,
    #[serde(default)]
    pub waf_bypass_verify: Vec<WafBypassVerifyTemplate>,
    #[serde(default)]
    pub header_scorecard: Vec<HeaderScorecardTemplate>,
    #[serde(default)]
    pub reputation_audit: Vec<ReputationAuditTemplate>,
    #[serde(default)]
    pub ct_log_audit: Vec<CtLogAuditTemplate>,
    #[serde(default)]
    pub remediation_gen: Vec<RemediationGenTemplate>,
    #[serde(default)]
    pub mitre_mapping: Vec<MitreMappingTemplate>,
    #[serde(default)]
    pub container_audit: Vec<ContainerAuditTemplate>,
    #[serde(default)]
    pub k8s_audit: Vec<K8sAuditTemplate>,
    #[serde(default)]
    pub sast_taint: Vec<SastTaintTemplate>,
    #[serde(default)]
    pub sast_secrets: Vec<SastSecretsTemplate>,
    #[serde(default)]
    pub subdomain_takeover: Vec<SubdomainTakeoverTemplate>,
    #[serde(default)]
    pub port_scan: Vec<PortScanTemplate>,
    #[serde(default)]
    pub schema_drift: Vec<SchemaDriftTemplate>,
    #[serde(default)]
    pub pii_leak_audit: Vec<PiiLeakAuditTemplate>,
    #[serde(default)]
    pub cicd_audit: Vec<CicdAuditTemplate>,
    #[serde(default)]
    pub dependency_audit: Vec<DependencyAuditTemplate>,
    #[serde(default)]
    pub easm: Vec<EasmTemplate>,
    #[serde(default)]
    pub web3_audit: Vec<Web3AuditTemplate>,
    #[serde(default)]
    pub mobile_audit: Vec<MobileAuditTemplate>,
    #[serde(default)]
    pub serverless_audit: Vec<ServerlessAuditTemplate>,
    #[serde(default)]
    pub auto_exploit: Vec<AutoExploitTemplate>,
    #[serde(default)]
    pub ui_proxy: Vec<UiProxyTemplate>,
    #[serde(default)]
    pub oob_interaction: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TemplateInfo {
    pub name: String,
    pub severity: String,
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub compliance: std::collections::HashMap<String, String>,
}

impl VulnerabilityTemplate {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, crate::core::error::ScannerError> {
        let content = std::fs::read_to_string(path)?;
        Self::load_from_str(&content)
    }

    pub fn load_from_str(content: &str) -> Result<Self, crate::core::error::ScannerError> {
        // Detect and convert OpenAPI/Swagger JSON specifications dynamically
        if content.trim().starts_with('{') && (content.contains("\"openapi\"") || content.contains("\"swagger\"")) {
            if let Ok(generated) = crate::features::crawler::parsers::openapi_generator::generate_template_from_openapi(content) {
                return Ok(generated);
            }
        }

        let template: VulnerabilityTemplate = serde_yaml::from_str(content)?;
        template.validate()?;
        Ok(template)
    }

    /// Validate the template for required fields and consistency.
    /// Returns an error with a description of what is invalid.
    pub fn validate(&self) -> Result<(), crate::core::error::ScannerError> {
        use crate::core::error::ScannerError;

        if self.id.trim().is_empty() {
            return Err(ScannerError::TemplateValidationError(
                "template id must not be empty".to_string()
            ));
        }

        if self.info.name.trim().is_empty() {
            return Err(ScannerError::TemplateValidationError(
                "template info.name must not be empty".to_string()
            ));
        }

        // Validate severity is a recognized value
        let valid_severities = ["info", "low", "medium", "high", "critical"];
        let sev = self.info.severity.to_lowercase();
        if !sev.is_empty() && !valid_severities.contains(&sev.as_str()) {
            return Err(ScannerError::TemplateValidationError(
                format!("invalid severity '{}'. Must be one of: {:?}", self.info.severity, valid_severities)
            ));
        }

        // At least one request/network/dns/tls/script or feature-specific block must be defined
        let has_any_definition = !self.requests.is_empty()
            || !self.network.is_empty()
            || !self.dns.is_empty()
            || !self.tls.is_empty()
            || !self.scripts.is_empty()
            || !self.fuzz.is_empty()
            || !self.cloud.is_empty()
            || !self.logic.is_empty()
            || !self.deep_analysis.is_empty()
            || !self.iac_audit.is_empty()
            || !self.drift_detect.is_empty()
            || !self.easm.is_empty()
            || !self.web3_audit.is_empty()
            || !self.mobile_audit.is_empty()
            || !self.serverless_audit.is_empty()
            || !self.auto_exploit.is_empty()
            || !self.ui_proxy.is_empty()
            || !self.oob_interaction;

        if !has_any_definition {
            return Err(ScannerError::TemplateValidationError(
                "template must define at least one request, network, dns, tls, script, or feature block".to_string()
            ));
        }

        Ok(())
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
        assert!(result.is_err(), "Serde should reject unknown fields");
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
    min_version: "TLSv1.2"
    matchers:
      - type: expired
        part: body
        "#;
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", yaml).unwrap();

        let template = VulnerabilityTemplate::load(file.path()).unwrap();
        assert!(!template.dns.is_empty());
        assert!(!template.tls.is_empty());
        assert_eq!(template.tls[0].min_version.as_deref(), Some("TLSv1.2"));
    }
}
