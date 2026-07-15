use crate::core::result::ScanResult;
use crate::network::http::StealthHttpClient;
use crate::template::schema::TemplateInfo;
use chrono::Utc;
use std::sync::Arc;
use urlencoding::encode;
use super::parser::WafBypassVerifyTemplate;

pub async fn execute(
    target_host: &str,
    http_client: &StealthHttpClient,
    templates: &[WafBypassVerifyTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_host);

        for payload in &template.payloads {
            // Test query parameter injection for V1 MVP replacement
            let test_url = format!("{}/?q={}", host, encode(payload));

            tracing::debug!(target = %host, payload = %payload, "Sending WAF evasion payload");

            match http_client.send_request(&host, "GET", &test_url, None, None).await {
                Ok(response) => {
                    let status = response.status().as_u16();

                    // 403 Forbidden or 406 Not Acceptable are typical WAF blocks.
                    // 200 OK means the WAF didn't block the malicious payload.
                    if status != 403 && status != 406 && status != 429 {
                        return Some(ScanResult {
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: "High".to_string(), // Bypassing WAF is high severity
                            target: host.clone(),
                            payload: format!(
                                "Payload '{}' bypassed WAF filtering. Target returned HTTP {}.",
                                payload, status
                            ),
                            compliance: Default::default(),
                        });
                    }
                }
                Err(e) => {
                    tracing::trace!("WAF verify request failed: {}", e);
                }
            }
        }
    }
    None
}
