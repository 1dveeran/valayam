use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use chrono::Utc;
use regex::Regex;
use super::parser::ClientSecretAuditTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[ClientSecretAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.get_client();
            if let Ok(resp) = req_client.get(reqwest_url).send().await {
                if let Ok(body) = resp.text().await {
                    // Check for client-side hardcoded secrets (e.g. AWS keys exposed in JS bundles)
                    let secret_re = Regex::new(r#"(?i)(api_key|apikey|secret|password|passwd|pwd|aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['""][a-zA-Z0-9/+=]{10,}['""]"#).unwrap();
                    
                    if secret_re.is_match(&body) {
                        return Some(ScanResult {
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: "High".to_string(),
                            target: host.clone(),
                            payload: "Hardcoded client secret or API token found in client-side bundle response.".to_string(),
                            compliance: Default::default(),
                        });
                    }
                }
            }
        }
    }
    None
}
