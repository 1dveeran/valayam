use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use super::parser::CtLogAuditTemplate;
use chrono::Utc;
use std::collections::HashMap;

pub async fn execute(
    templates: &[CtLogAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
    client: &StealthHttpClient,
) -> Option<ScanResult> {
    for template in templates {
        let crt_sh_url = format!("https://crt.sh/?q=%.{}&output=json", template.query_domain);

        if let Ok(resp) = client.send_request("GET", &crt_sh_url, None, None).await {
            if resp.status().is_success() {
                if let Ok(body) = resp.text().await {
                    // MVP: Just check if we got a JSON array back that is not empty
                    if body.starts_with('[') && body.len() > 10 {
                        let mut compliance = HashMap::new();
                        compliance.insert("recon".to_string(), "OSINT".to_string());
                        
                        return Some(ScanResult {
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: "Info".to_string(),
                            target: template.query_domain.clone(),
                            payload: "Subdomains discovered via Certificate Transparency logs (crt.sh).".to_string(),
                            cvss_score: None,
                            reference: None,
                            solution: None,
                            tags: Vec::new(),
                            compliance,
                        });
                    }
                }
            }
        }
    }
    None
}
