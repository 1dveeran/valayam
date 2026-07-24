use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use crate::network::http::StealthHttpClient;
use valayam_models::templates::idp_audit::IdpAuditTemplate;

pub async fn execute(
    templates: &[IdpAuditTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
    client: &StealthHttpClient,
    base_url: &str,
) -> Option<FindingOwned> {
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
            let mut finding = FindingOwned::from_template_and_info(
                template_id,
                template_meta,
                url.clone(),
                format!("Exposed Identity Provider (IDP) discovery/sign-on endpoints detected: {:?}", findings),
            );
            finding.severity = "Medium".to_string();
            finding.metadata.insert("cwe".to_string(), "CWE-16".to_string());
            return Some(finding);
        }
    }
    None
}