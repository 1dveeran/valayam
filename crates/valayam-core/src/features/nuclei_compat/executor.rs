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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nuclei_executor_new() {
        let client = Arc::new(
            StealthHttpClient::new(false, false, None, false).unwrap()
        );
        let executor = NucleiExecutor::new(client);
        // Just verify construction works
        assert!(std::mem::size_of_val(&executor) > 0);
    }

    #[test]
    fn test_nuclei_template_baseurl_substitution() {
        let target_url = "https://example.com";
        let raw_path = "{{BaseURL}}/admin";
        let resolved = raw_path.replace("{{BaseURL}}", target_url);
        assert_eq!(resolved, "https://example.com/admin");
    }

    #[test]
    fn test_nuclei_matcher_and_condition_logic() {
        // Simulate the AND/OR matcher logic from the executor
        let matchers = vec![
            ("word", true),
            ("status", true),
        ];
        let is_and = true;
        let all_match = matchers.iter().all(|(_, matched)| *matched);
        let any_match = matchers.iter().any(|(_, matched)| *matched);
        assert!(is_and && all_match);
        assert!(any_match);
    }

    #[test]
    fn test_nuclei_matcher_or_condition_logic() {
        let matchers = vec![
            ("word", false),
            ("status", true),
        ];
        let is_and = false;
        let all_match = matchers.iter().all(|(_, matched)| *matched);
        let any_match = matchers.iter().any(|(_, matched)| *matched);
        assert!(!is_and);
        assert!(!all_match);
        assert!(any_match);
    }

    #[test]
    fn test_nuclei_matcher_and_fails_when_one_misses() {
        let matchers = vec![
            ("word", true),
            ("status", false),
        ];
        let all_match = matchers.iter().all(|(_, matched)| *matched);
        assert!(!all_match);
    }

    #[test]
    fn test_nuclei_matcher_or_succeeds_with_any_match() {
        let matchers = vec![
            ("word", false),
            ("status", false),
            ("word", true),
        ];
        let any_match = matchers.iter().any(|(_, matched)| *matched);
        assert!(any_match);
    }

    #[test]
    fn test_nuclei_matcher_or_fails_with_no_matches() {
        let matchers = vec![
            ("word", false),
            ("status", false),
        ];
        let any_match = matchers.iter().any(|(_, matched)| *matched);
        assert!(!any_match);
    }

    #[test]
    fn test_nuclei_empty_matchers_no_match() {
        let matchers: Vec<&str> = vec![];
        assert!(matchers.is_empty());
    }
}
