use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use chrono::Utc;
use super::parser::HeaderScorecardTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[HeaderScorecardTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.get_client();
            if let Ok(resp) = req_client.get(reqwest_url).send().await {
                let headers = resp.headers();
                let mut missing = Vec::new();
                for req_header in &template.required_headers {
                    if !headers.contains_key(req_header) {
                        missing.push(req_header.clone());
                    }
                }
                
                if !missing.is_empty() {
                    return Some(ScanResult {
                        timestamp: Utc::now(),
                        template_id: template_id.to_string(),
                        template_name: template_info.name.clone(),
                        template_severity: "Low".to_string(),
                        target: host.clone(),
                        payload: format!("Missing recommended security headers: {:?}", missing),
                        compliance: Default::default(),
                    });
                }
            }
        }
    }
    None
}
