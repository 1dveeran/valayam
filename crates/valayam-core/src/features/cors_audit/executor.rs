use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use chrono::Utc;
use super::parser::CorsAuditTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[CorsAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.get_client();
            // Send an Origin header to test CORS reflection
            if let Ok(resp) = req_client.get(reqwest_url).header("Origin", "https://evil.com").send().await {
                let headers = resp.headers();
                let allow_origin = headers.get("access-control-allow-origin").and_then(|v| v.to_str().ok()).unwrap_or("");
                let allow_creds = headers.get("access-control-allow-credentials").and_then(|v| v.to_str().ok()).unwrap_or("false");
                
                // If it reflects arbitrary origin or allows * with credentials, it's a critical CORS misconfiguration
                if (allow_origin == "https://evil.com" || allow_origin == "*") && allow_creds == "true" {
                    return Some(ScanResult {
                        timestamp: Utc::now(),
                        template_id: template_id.to_string(),
                        template_name: template_info.name.clone(),
                        template_severity: "High".to_string(),
                        target: host.clone(),
                        payload: "Insecure CORS policy: Reflects arbitrary Origin with Access-Control-Allow-Credentials set to true.".to_string(),
                        compliance: Default::default(),
                    });
                }
            }
        }
    }
    None
}
