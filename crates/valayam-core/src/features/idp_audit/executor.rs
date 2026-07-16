use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use super::parser::IdpAuditTemplate;
use chrono::Utc;
use std::collections::HashMap;

pub async fn execute(
    templates: &[IdpAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
    client: &StealthHttpClient,
    base_url: &str,
) -> Option<ScanResult> {
    for template in templates {
        let url = if template.target.starts_with("http") {
            template.target.clone()
        } else {
            format!("{}/{}", base_url.trim_end_matches('/'), template.target.trim_start_matches('/'))
        };
        
        let idp_endpoints = vec![
            "/adfs/ls/idpinitiatedsignon.htm", // Common ADFS endpoint that can be abused for enumeration
            "/oauth2/default/.well-known/openid-configuration", // Okta discovery
        ];

        let mut findings = Vec::new();

        for endpoint in idp_endpoints {
            let test_url = format!("{}{}", url.trim_end_matches('/'), endpoint);
            if let Ok(resp) = client.send_request("GET", &test_url, None, None).await {
                if resp.status().is_success() {
                    findings.push(endpoint.to_string());
                }
            }
        }

        if !findings.is_empty() {
            let mut compliance = HashMap::new();
            compliance.insert("cwe".to_string(), "CWE-16".to_string());
            
            return Some(ScanResult {
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: "Medium".to_string(),
                target: url,
                payload: format!("Exposed Identity Provider (IDP) discovery/sign-on endpoints detected: {:?}", findings),
                cvss_score: None,
                reference: None,
                solution: None,
                tags: Vec::new(),
                compliance,
            });
        }
    }
    None
}
