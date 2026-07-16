use crate::core::result::ScanResult;
use crate::network::http::StealthHttpClient;
use super::matchers::evaluate_words_stream;
use super::parser::NucleiTemplate;
use std::sync::Arc;

#[derive(Clone)]
pub struct NucleiExecutor {
    client: Arc<StealthHttpClient>,
}

impl NucleiExecutor {
    pub fn new(client: Arc<StealthHttpClient>) -> Self {
        Self { client }
    }

    pub async fn execute_scan(
        &self,
        target_url: &str,
        template: NucleiTemplate,
    ) -> Option<ScanResult> {
        let mut finding_payload = String::new();
        let mut found_vulnerability = false;

        // Iterate over Nuclei requests
        for req_rule in &template.requests {
            // Nuclei supports multiple paths per request
            for raw_path in &req_rule.path {
                // Nuclei Variable Substitution
                let resolved_path = raw_path.replace("{{BaseURL}}", target_url);

                tracing::debug!(target = %target_url, method = %req_rule.method, path = %resolved_path, "Sending Nuclei HTTP request");
                let Ok(resp) = self
                    .client
                    .send_request(
                        &req_rule.method,
                        &resolved_path,
                        req_rule.headers.as_ref(),
                        None,
                    )
                    .await
                else {
                    tracing::debug!("Nuclei request failed or timed out to {}", target_url);
                    continue;
                };

                let status = resp.status().as_u16();
                let Ok(body_bytes) = resp.bytes().await else {
                    tracing::debug!("Failed to read Nuclei response body from {}", target_url);
                    continue;
                };

                tracing::trace!(
                    status = %status,
                    body_preview = %String::from_utf8_lossy(&body_bytes).chars().take(200).collect::<String>(),
                    "Received Nuclei HTTP response"
                );

                let match_successful = if req_rule.matchers.is_empty() {
                    false
                } else {
                    // matchers-condition is AND or OR
                    let is_and = req_rule.matchers_condition.to_lowercase() == "and";

                    let mut all_match = true;
                    let mut any_match = false;

                    for matcher in &req_rule.matchers {
                        let matched = if matcher.r#type == "word" {
                            evaluate_words_stream(&body_bytes, &matcher.words)
                        } else if matcher.r#type == "status" {
                            matcher
                                .status
                                .as_ref()
                                .is_some_and(|s| s.contains(&status))
                        } else {
                            false
                        };

                        if matched {
                            any_match = true;
                        } else {
                            all_match = false;
                        }
                    }

                    if is_and { all_match } else { any_match }
                };

                if match_successful {
                    tracing::debug!(target = %target_url, template = %template.id, "Vulnerability Nuclei match found");
                    found_vulnerability = true;
                    finding_payload = format!("Nuclei HTTP Match on: {}", resolved_path);
                    break;
                }
            }

            if found_vulnerability {
                break; // Stop evaluating further requests if we already found a vulnerability for this template
            }
        }

        if found_vulnerability {
            Some(ScanResult {
                target: target_url.to_string(),
                template_name: template.info.name,
                template_id: template.id,
                template_severity: template.info.severity,
                payload: finding_payload,
                timestamp: chrono::Utc::now(),
                cvss_score: None,
                reference: None,
                solution: None,
                tags: Vec::new(),
                compliance: Default::default(),
            })
        } else {
            None
        }
    }
}
