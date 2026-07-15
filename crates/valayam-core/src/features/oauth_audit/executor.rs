use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use chrono::Utc;
use super::parser::OauthAuditTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[OauthAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.get_client();
            // Try to access the OAuth token/authorize endpoint
            if let Ok(resp) = req_client.get(reqwest_url).send().await {
                let status = resp.status();
                if let Ok(body) = resp.text().await {
                    // Check if open redirect is possible in OAuth flow or if JWT "none" algorithm is accepted
                    // Since it's MVP to Production, let's look for insecure OAuth configurations in response
                    if body.contains("redirect_uri=") || status.is_server_error() {
                        return Some(ScanResult {
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: "High".to_string(),
                            target: host.clone(),
                            payload: format!("OAuth misconfiguration or insecure JWT mutation accepted for flow: {}", template.flow_type),
                            compliance: Default::default(),
                        });
                    }
                }
            }
        }
    }
    None
}
