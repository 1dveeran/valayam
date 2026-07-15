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
                    } else {
                        // The payload WAS blocked. Let's try evasive permutations!
                        let permutations = super::permutator::WafPermutator::generate_permutations(payload);
                        
                        for evaded_payload in permutations {
                            let evaded_url = format!("{}/?q={}", host, evaded_payload);
                            if let Ok(evaded_resp) = http_client.send_request(&host, "GET", &evaded_url, None, None).await {
                                let ev_status = evaded_resp.status().as_u16();
                                if ev_status != 403 && ev_status != 406 && ev_status != 429 {
                                    return Some(ScanResult {
                                        timestamp: Utc::now(),
                                        template_id: template_id.to_string(),
                                        template_name: format!("{} - Evasion Successful", template_info.name),
                                        template_severity: "Critical".to_string(),
                                        target: host.clone(),
                                        payload: format!(
                                            "WAF blocked initial payload, but evasive mutation '{}' successfully bypassed filtering (HTTP {}).",
                                            evaded_payload, ev_status
                                        ),
                                        compliance: Default::default(),
                                    });
                                }
                            }
                        }

                        // Also try HPP
                        let hpp_urls = super::permutator::WafPermutator::generate_hpp_urls(&host, "q", payload);
                        for hpp_url in hpp_urls {
                            if let Ok(hpp_resp) = http_client.send_request(&host, "GET", &hpp_url, None, None).await {
                                let hpp_status = hpp_resp.status().as_u16();
                                if hpp_status != 403 && hpp_status != 406 && hpp_status != 429 {
                                    return Some(ScanResult {
                                        timestamp: Utc::now(),
                                        template_id: template_id.to_string(),
                                        template_name: format!("{} - HPP Evasion Successful", template_info.name),
                                        template_severity: "Critical".to_string(),
                                        target: host.clone(),
                                        payload: format!(
                                            "WAF blocked initial payload, but HTTP Parameter Pollution successfully bypassed filtering: {}",
                                            hpp_url
                                        ),
                                        compliance: Default::default(),
                                    });
                                }
                            }
                        }
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
