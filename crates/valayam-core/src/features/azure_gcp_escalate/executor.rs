use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use chrono::Utc;
use super::parser::AzureGcpEscalateTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[AzureGcpEscalateTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.get_client();
            // Simulate SSRF check for GCP/Azure Metadata
            let payload_url = if template.provider == "gcp" {
                "http://metadata.google.internal/computeMetadata/v1/"
            } else {
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
            };

            if let Ok(resp) = req_client.get(reqwest_url.clone())
                .query(&[("url", payload_url)])
                .send().await {
                
                if let Ok(body) = resp.text().await {
                    if (template.provider == "gcp" && body.contains("instance/")) || (template.provider == "azure" && body.contains("compute")) {
                        return Some(ScanResult {
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: "Critical".to_string(),
                            target: host.clone(),
                            payload: format!("Azure/GCP Escalate: SSRF vulnerability leading to {} metadata exposure detected.", template.provider),
                            compliance: Default::default(),
                        });
                    }
                }
            }
        }
    }
    None
}
