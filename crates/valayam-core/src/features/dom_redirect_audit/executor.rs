use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use crate::network::http::StealthHttpClient;
use regex::Regex;
use valayam_models::templates::dom_redirect_audit::DomRedirectAuditTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[DomRedirectAuditTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.client();
            if let Ok(resp) = req_client.get(reqwest_url).send().await {
                if let Ok(body) = resp.text().await {
                    // Look for common DOM-based open redirect patterns in the JS body
                    // E.g., window.location = location.hash / location.search
                    let dom_re = Regex::new(r"(?i)(window\.location|location\.href|location\.replace)\s*=\s*[^;]*(location\.hash|location\.search|window\.location\.search)").unwrap();
                    
                    if dom_re.is_match(&body) {
                        let mut finding = FindingOwned::from_template_and_info(
                            template_id,
                            template_meta,
                            host.clone(),
                            "DOM-based Open Redirect vulnerability pattern detected in JavaScript.".to_string(),
                        );
                        finding.severity = "High".to_string();
                        return Some(finding);
                    }
                }
            }
        }
    }
    None
}
