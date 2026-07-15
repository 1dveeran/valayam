use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use chrono::Utc;
use super::parser::AwsEscalateTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[AwsEscalateTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.get_client();
            // Simulate SSRF check for AWS IMDSv1
            if let Ok(resp) = req_client.get(reqwest_url.clone())
                .query(&[("url", "http://169.254.169.254/latest/meta-data/")])
                .send().await {
                
                if let Ok(body) = resp.text().await {
                    if body.contains("ami-id") && body.contains("instance-id") {
                        return Some(ScanResult {
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: "Critical".to_string(),
                            target: host.clone(),
                            payload: "AWS Escalate: SSRF vulnerability leading to AWS IMDSv1 metadata exposure detected.".to_string(),
                            compliance: Default::default(),
                        });
                    }
                }
            }
        }
    }
    None
}
