use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use crate::network::http::StealthHttpClient;
use valayam_models::templates::header_scorecard::HeaderScorecardTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[HeaderScorecardTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.client();
            if let Ok(resp) = req_client.get(reqwest_url).send().await {
                let headers = resp.headers();
                let mut missing = Vec::new();
                for req_header in &template.required_headers {
                    if !headers.contains_key(req_header) {
                        missing.push(req_header.clone());
                    }
                }
                
                if !missing.is_empty() {
                    return Some(FindingOwned::from_template_and_info(
                        template_id,
                        template_meta,
                        &host,
                        format!("Missing recommended security headers: {:?}", missing),
                    ));
                }
            }
        }
    }
    None
}
