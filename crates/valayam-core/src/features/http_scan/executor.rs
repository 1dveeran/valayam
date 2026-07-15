use crate::core::result::ScanResult;
use crate::core::variables::resolve_variables;
use crate::features::extractors::engine::extract_from_response;
use crate::features::helpers::parser::evaluate_helpers;
use crate::network::http::StealthHttpClient;
use crate::template::schema::TemplateInfo;
use super::parser::HttpRequestTemplate;
use chrono::Utc;
use regex::bytes::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

// ── Built-in Sensitive Patterns ─────────────────────────────────────────
// Modern Rust Feature: LazyLock compiles these heavy regexes exactly ONCE
// at runtime, making them thread-safe and instantly available to all async workers.
static SENSITIVE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"root:x:[0-9]+:[0-9]+:").unwrap(),
        Regex::new(r"(?i)DB_PASSWORD=").unwrap(),
        Regex::new(r#"\"args\":\s*\{"#).unwrap(), // Matches httpbin.org payload reflection
    ]
});

/// Evaluates raw byte slices without allocating expensive String copies in memory.
/// Checks both hardcoded sensitive patterns and custom template-defined patterns.
fn evaluate_stream(body_bytes: &[u8], customized_patterns: &[String]) -> bool {
    // 1. Fast global check (Zero-Day indicators hardcoded in engine)
    for re in SENSITIVE_PATTERNS.iter() {
        if re.is_match(body_bytes) {
            return true;
        }
    }

    // 2. Custom template check (from the YAML file)
    for pattern in customized_patterns {
        // Modern let-else: if the user wrote a bad regex, skip it safely
        let Ok(re) = Regex::new(pattern) else {
            continue;
        };
        if re.is_match(body_bytes) {
            return true;
        }
    }

    false
}

/// Resolves all variable placeholders and helper functions in a string.
/// Pipeline: raw string → variable substitution → helper evaluation.
fn resolve_all(template_str: &str, context: &HashMap<String, String>) -> String {
    let with_vars = resolve_variables(template_str, context);
    evaluate_helpers(&with_vars)
}

/// Executes all HTTP request rules from a template against the target.
///
/// Supports the full extraction pipeline:
/// 1. Resolve `{{variables}}` and `{{helpers()}}` in path, headers, and body
/// 2. Send the request
/// 3. Run matchers against the response
/// 4. Run extractors to capture values into the shared variable context
///
/// Returns the first finding (ScanResult) or None if no matchers triggered.
pub async fn execute(
    client: &StealthHttpClient,
    target_url: &str,
    requests: &[HttpRequestTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
    variables: &mut HashMap<String, String>,
) -> Option<ScanResult> {
    for req_rule in requests {
        // ── Resolve all placeholders in path, headers, and body ──
        let resolved_path = resolve_all(&req_rule.path, variables);

        let resolved_headers = req_rule.headers.as_ref().map(|h| {
            h.iter()
                .map(|(k, v)| (k.clone(), resolve_all(v, variables)))
                .collect::<HashMap<String, String>>()
        });

        let resolved_body = req_rule.body.as_ref().map(|b| resolve_all(b, variables));

        tracing::trace!(
            target = %target_url,
            method = %req_rule.method,
            path = %resolved_path,
            headers = ?resolved_headers,
            body = ?resolved_body,
            "Prepared raw HTTP request payload"
        );

        // ── Send HTTP request ──
        tracing::debug!(target = %target_url, method = %req_rule.method, path = %resolved_path, "Sending HTTP request");
        
        let resp = match client
            .send_request(
                target_url,
                &req_rule.method,
                &resolved_path,
                resolved_headers.as_ref(),
                resolved_body.as_deref(),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(target = %target_url, error = %e, "Request failed or timed out");
                continue;
            }
        };

        let status = resp.status().as_u16();

        // Capture response headers for extraction
        let resp_headers: HashMap<String, String> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str().ok().map(|val| (k.as_str().to_string(), val.to_string()))
            })
            .collect();

        let body_bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(target = %target_url, error = %e, "Failed to read response body");
                continue;
            }
        };

        tracing::trace!(
            status = %status,
            headers = ?resp_headers,
            body_preview = %String::from_utf8_lossy(&body_bytes).chars().take(200).collect::<String>(),
            "Received HTTP response"
        );

        // ── Run extractors (always, even if matchers fail) ──
        if !req_rule.extractors.is_empty() {
            let extracted = extract_from_response(
                &req_rule.extractors,
                &body_bytes,
                &resp_headers,
            );
            // Merge extracted values into the shared context
            for (key, value) in extracted {
                variables.insert(key, value);
            }
        }

        // ── Evaluate matchers ──
        tracing::debug!(status = %status, response_len = %body_bytes.len(), "Evaluating matchers");
        
        let all_matchers_succeeded = if req_rule.matchers.is_empty() {
            false
        } else {
            req_rule.matchers.iter().all(|matcher| {
                if matcher.r#type == "regex" && matcher.part == "body" {
                    evaluate_stream(&body_bytes, &matcher.regex)
                } else if matcher.r#type == "status" {
                    matcher
                        .status
                        .as_ref()
                        .is_some_and(|s| s.contains(&status))
                } else {
                    false
                }
            })
        };

        if all_matchers_succeeded {
            tracing::debug!("Vulnerability match found for template {}", template_id);
            return Some(ScanResult {
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: template_info.severity.clone(),
                target: target_url.to_string(),
                payload: resolved_path,
                compliance: Default::default(),
            });
        }
    }

    None
}
