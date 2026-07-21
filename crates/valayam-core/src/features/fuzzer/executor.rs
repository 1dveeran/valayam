use crate::core::result::ScanResult;
use crate::network::http::StealthHttpClient;
use crate::template::schema::TemplateInfo;
use super::parser::FuzzTemplate;
use chrono::Utc;
use url::Url;

fn mutate_query_url(
    base_url: &Url,
    query_params: &[(String, String)],
    target_key: &str,
    payload: &str,
) -> String {
    let mut mutated_url = base_url.clone();
    {
        let mut query_serializer = mutated_url.query_pairs_mut();
        query_serializer.clear();
        for (k, v) in query_params {
            if k == target_key {
                query_serializer.append_pair(k, payload);
            } else {
                query_serializer.append_pair(k, v);
            }
        }
    }
    mutated_url.to_string()
}

/// Mutates and executes requests based on configured fuzzer template keys and payloads.
pub async fn execute(
    client: &StealthHttpClient,
    target_url: &str,
    fuzz_rules: &[FuzzTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    let Ok(base_url) = Url::parse(target_url) else {
        return None;
    };

    for rule in fuzz_rules {
        if rule.part == "query" {
            // Collect existing query parameters
            let query_params: Vec<(String, String)> = base_url.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            if query_params.is_empty() {
                continue;
            }

            for (key, _) in &query_params {
                // If keys list is not empty, restrict fuzzing targets to designated keys
                if !rule.keys.is_empty() && !rule.keys.contains(key) {
                    continue;
                }

                for payload in &rule.payloads {
                    // Mutate query parameters cleanly in helper
                    let url_str = mutate_query_url(&base_url, &query_params, key, payload);

                    // Send mutated request
                    if let Ok(resp) = client.send_request("GET", &url_str, None, None).await {
                        let status_code = resp.status().as_u16();
                        let body_text = resp.text().await.unwrap_or_default();

                        // Evaluate matchers
                        for matcher in &rule.matchers {
                            if matcher.r#type == "status" {
                                if let Some(ref statuses) = matcher.status {
                                    if statuses.contains(&status_code) {
                                        return Some(ScanResult {
                                            cvss_score: None,
                                            reference: None,
                                            solution: None,
                                            tags: Vec::new(),
                                            timestamp: Utc::now(),
                                            template_id: template_id.to_string(),
                                            template_name: template_info.name.clone(),
                                            template_severity: template_info.severity.clone(),
                                            target: target_url.to_string(),
                                            payload: format!("Fuzz matched status {} on query key '{}' with payload '{}'", status_code, key, payload),
                                            compliance: Default::default(),
                                        });
                                    }
                                }
                            } else if matcher.r#type == "regex" && matcher.part == "body" {
                                for pattern in &matcher.regex {
                                    if let Ok(re) = regex::Regex::new(pattern) {
                                        if re.is_match(&body_text) {
                                            return Some(ScanResult {
                                            cvss_score: None,
                                            reference: None,
                                            solution: None,
                                            tags: Vec::new(),
                                                timestamp: Utc::now(),
                                                template_id: template_id.to_string(),
                                                template_name: template_info.name.clone(),
                                                template_severity: template_info.severity.clone(),
                                                target: target_url.to_string(),
                                                payload: format!("Fuzz matched regex '{}' on query key '{}' with payload '{}'", pattern, key, payload),
                                                compliance: Default::default(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_query_mutation() {
        // Test the core mutation logic directly without needing an HTTP server or client.
        // This avoids nested-runtime issues from mockito or reqwest inside #[tokio::test].
        let base = Url::parse("https://example.com/search?q=hello&page=1").unwrap();
        let params: Vec<(String, String)> = base
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        // Mutate the "q" parameter with an SQL injection payload
        let result = mutate_query_url(&base, &params, "q", "' OR 1=1--");
        assert!(
            result.contains("q="),
            "Mutated URL should contain the q parameter: {}",
            result
        );
        assert!(
            result.contains("page=1"),
            "Other query parameters should be preserved: {}",
            result
        );
        assert!(
            !result.contains("q=hello"),
            "Original q value should be replaced: {}",
            result
        );

        // Mutate a non-existent key — original params should be unchanged
        let no_change = mutate_query_url(&base, &params, "nonexistent", "payload");
        assert!(
            no_change.contains("q=hello"),
            "Non-targeted key should not be mutated: {}",
            no_change
        );
        assert!(
            no_change.contains("page=1"),
            "Other params should be preserved: {}",
            no_change
        );
    }
}
