use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use chrono::Utc;
use super::parser::CspAuditTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[CspAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.client();
            if let Ok(resp) = req_client.get(reqwest_url).send().await {
                if let Some(csp) = resp.headers().get("content-security-policy") {
                    if let Ok(csp_str) = csp.to_str() {
                        let is_unsafe = csp_str.contains("unsafe-inline") || csp_str.contains("unsafe-eval");
                        if is_unsafe {
                            return Some(ScanResult {
                                timestamp: Utc::now(),
                                template_id: template_id.to_string(),
                                template_name: template_info.name.clone(),
                                template_severity: "Low".to_string(),
                                target: host.clone(),
                                payload: "Insecure Content-Security-Policy (CSP) with 'unsafe-inline' or 'unsafe-eval' detected.".to_string(),
                                cvss_score: None,
                                reference: None,
                                solution: None,
                                tags: Vec::new(),
                                compliance: Default::default(),
                            });
                        }
                    }
                } else {
                    // Missing CSP entirely could also be an issue, but we'll stick to MVP description (detecting unsafe-inline)
                }
            }
        }
    }
    None
}
