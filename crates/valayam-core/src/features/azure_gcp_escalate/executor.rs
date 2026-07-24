use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use crate::network::http::StealthHttpClient;
use valayam_models::templates::azure_gcp_escalate::AzureGcpEscalateTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[AzureGcpEscalateTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.client();
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
                        let mut finding = FindingOwned::from_template_and_info(
                            template_id,
                            template_meta,
                            host.clone(),
                            format!("Azure/GCP Escalate: SSRF vulnerability leading to {} metadata exposure detected.", template.provider),
                        );
                        finding.severity = "Critical".to_string();
                        return Some(finding);
                    }
                }
            }
        }
    }
    None
}