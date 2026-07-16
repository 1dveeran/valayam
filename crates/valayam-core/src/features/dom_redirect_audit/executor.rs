use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use chrono::Utc;
use regex::Regex;
use super::parser::DomRedirectAuditTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[DomRedirectAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.client();
            if let Ok(resp) = req_client.get(reqwest_url).send().await {
                if let Ok(body) = resp.text().await {
                    // Look for common DOM-based open redirect patterns in the JS body
                    // E.g., window.location = location.hash / location.search
                    let dom_re = Regex::new(r"(?i)(window\.location|location\.href|location\.replace)\s*=\s*[^;]*(location\.hash|location\.search|window\.location\.search)").unwrap();
                    
                    if dom_re.is_match(&body) {
                        return Some(ScanResult {
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: "High".to_string(),
                            target: host.clone(),
                            payload: "DOM-based Open Redirect vulnerability pattern detected in JavaScript.".to_string(),
                            cvss_score: None,
                            reference: None,
                            solution: None,
                            tags: Vec::new(),
                            compliance: Default::default(),
                        });
                    }
                }
            }
        }
    }
    None
}
