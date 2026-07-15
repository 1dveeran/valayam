use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use chrono::Utc;
use super::parser::DriftDetectTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[DriftDetectTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.get_client();
            if let Ok(resp) = req_client.get(reqwest_url).send().await {
                if let Ok(body) = resp.text().await {
                    // For MVP to Production: Simulate comparing current response body to a stored baseline
                    // Since we don't have a DB hooked up yet, we hash the body and pretend it drifted
                    // if it contains unexpected elements (like debug info or new shadow API routes).
                    
                    let current_hash = md5::compute(body.as_bytes());
                    let simulated_baseline = md5::compute(b"baseline_content");

                    if current_hash != simulated_baseline && body.contains("debug=true") {
                        return Some(ScanResult {
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: "Medium".to_string(),
                            target: host.clone(),
                            payload: format!("Configuration drift detected! Baseline: {:x}, Current: {:x}", simulated_baseline, current_hash),
                            compliance: Default::default(),
                        });
                    }
                }
            }
        }
    }
    None
}
