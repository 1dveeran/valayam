use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use chrono::Utc;
use super::parser::SbomAuditTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[SbomAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);
        
        // Ensure host has a trailing slash for proper URL building, or trim it
        let base = host.trim_end_matches('/');
        let file_type = template.r#type.trim_start_matches('/');
        let url = format!("{}/{}", base, file_type);

        if let Ok(reqwest_url) = reqwest::Url::parse(&url) {
            let req_client = client.get_client();
            if let Ok(resp) = req_client.get(reqwest_url).send().await {
                if resp.status().is_success() {
                    return Some(ScanResult {
                        timestamp: Utc::now(),
                        template_id: template_id.to_string(),
                        template_name: template_info.name.clone(),
                        template_severity: "Medium".to_string(),
                        target: host.clone(),
                        payload: format!("Exposed SBOM/Manifest file detected at: {}", url),
                        compliance: Default::default(),
                    });
                }
            }
        }
    }
    None
}
