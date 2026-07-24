use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use crate::network::http::StealthHttpClient;
use valayam_models::templates::aws_escalate::AwsEscalateTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[AwsEscalateTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.client();
            // Simulate SSRF check for AWS IMDSv1
            if let Ok(resp) = req_client.get(reqwest_url)
                .query(&[("url", "http://169.254.169.254/latest/meta-data/")])
                .send().await {

                if let Ok(body) = resp.text().await {
                    if body.contains("ami-id") && body.contains("instance-id") {
                        let mut finding = FindingOwned::from_template_and_info(
                            template_id,
                            template_meta,
                            host.clone(),
                            "AWS Escalate: SSRF vulnerability leading to AWS IMDSv1 metadata exposure detected.".to_string(),
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