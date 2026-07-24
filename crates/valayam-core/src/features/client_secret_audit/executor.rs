use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use crate::network::http::StealthHttpClient;
use regex::Regex;
use valayam_models::templates::client_secret_audit::ClientSecretAuditTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[ClientSecretAuditTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.client();
            if let Ok(resp) = req_client.get(reqwest_url).send().await {
                if let Ok(body) = resp.text().await {
                    // Check for client-side hardcoded secrets (e.g. AWS keys exposed in JS bundles)
                    let secret_re = Regex::new(r#"(?i)(api_key|apikey|secret|password|passwd|pwd|aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['""][a-zA-Z0-9/+=]{10,}['""]"#).unwrap();
                    
                    if secret_re.is_match(&body) {
                        let mut finding = FindingOwned::from_template_and_info(
                            template_id,
                            template_meta,
                            host.clone(),
                            "Hardcoded client secret or API token found in client-side bundle response.".to_string(),
                        );
                        finding.severity = "High".to_string();
                        return Some(finding);
                    }
                }
            }
        }
    }
    None
}
