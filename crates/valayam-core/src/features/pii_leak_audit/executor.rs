use crate::core::result::ScanResult;
use valayam_models::templates::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use chrono::Utc;
use regex::Regex;
use valayam_models::templates::pii_leak_audit::PiiLeakAuditTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[PiiLeakAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);
        
        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.client();
            if let Ok(resp) = req_client.get(reqwest_url).send().await {
                if let Ok(body) = resp.text().await {
                    // Regex for basic PII (SSN and simple Credit Card check)
                    let ssn_re = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
                    let cc_re = Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap();

                    let mut found_pii = Vec::new();
                    if ssn_re.is_match(&body) {
                        found_pii.push("SSN");
                    }
                    if cc_re.is_match(&body) {
                        found_pii.push("Credit Card");
                    }

                    if !found_pii.is_empty() {
                        return Some(ScanResult { schema_version: "1.0.0".to_string(),
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: "High".to_string(),
                            target: host.clone(),
                            payload: format!("PII Leak Detected: Found potentially exposed data types: {:?}", found_pii),
                            cvss_score: None,
                            reference: None,
                            solution: None,
                            tags: Vec::new(),
                            compliance: Default::default(),
                        });
                    }
                }
            }
        }
    }
    None
}
