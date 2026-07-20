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
static SENSITIVE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"root:x:[0-9]+:[0-9]+:").unwrap(),
        Regex::new(r"(?i)DB_PASSWORD=").unwrap(),
        Regex::new(r#"\"args\":\s*\{"#).unwrap(),
        Regex::new(r"(?i)AKIA[0-9A-Z]{16}").unwrap(), // AWS Access Key
        Regex::new(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*").unwrap(), // JWT Token
        Regex::new(r#"(?i)api[_-]?key[\s=:"']+[A-Za-z0-9_=-]+"#).unwrap(), // Generic API Key
        Regex::new(r"(?i)BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY").unwrap(), // Private Keys
    ]
});

fn evaluate_stream(body_bytes: &[u8], customized_patterns: &[String]) -> bool {
    for re in SENSITIVE_PATTERNS.iter() {
        if re.is_match(body_bytes) {
            return true;
        }
    }
    for pattern in customized_patterns {
        let Ok(re) = Regex::new(pattern) else {
            continue;
        };
        if re.is_match(body_bytes) {
            return true;
        }
    }
    false
}

fn resolve_all(template_str: &str, context: &HashMap<String, String>) -> String {
    let with_vars = resolve_variables(template_str, context);
    evaluate_helpers(&with_vars)
}

fn matches_condition(
    matcher: &crate::core::matcher::ResponseMatcher,
    body_bytes: &[u8],
    resp_headers: &HashMap<String, String>,
    status: u16,
) -> bool {
    let mut is_match = false;

    if matcher.r#type == "regex" {
        if matcher.part == "body" {
            is_match = evaluate_stream(body_bytes, &matcher.regex);
        } else if matcher.part == "header" {
            let headers_str = resp_headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join("\r\n");
            
            for pattern in &matcher.regex {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if re.is_match(&headers_str) {
                        is_match = true;
                        break;
                    }
                }
            }
        }
    } else if matcher.r#type == "word" {
        if matcher.part == "body" {
            let body_str = String::from_utf8_lossy(body_bytes);
            is_match = matcher.words.iter().any(|w| body_str.contains(w));
        } else if matcher.part == "header" {
            let headers_str = resp_headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join("\r\n");
            is_match = matcher.words.iter().any(|w| headers_str.contains(w));
        }
    } else if matcher.r#type == "status" {
        is_match = matcher.status.as_ref().is_some_and(|s| s.contains(&status));
    }

    if matcher.negative {
        !is_match
    } else {
        is_match
    }
}

pub async fn execute(
    client: &StealthHttpClient,
    target_url: &str,
    requests: &[HttpRequestTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
    variables: &mut HashMap<String, String>,
) -> Vec<ScanResult> {
    let mut findings = Vec::new();

    for req_rule in requests {
        let resolved_path = resolve_all(&req_rule.path, variables);

        let full_url = if resolved_path.starts_with("http://") || resolved_path.starts_with("https://") {
            resolved_path.clone()
        } else {
            let base = target_url.trim_end_matches('/');
            let path = resolved_path.trim_start_matches('/');
            format!("{}/{}", base, path)
        };

        let resolved_headers = req_rule.headers.as_ref().map(|h| {
            h.iter()
                .map(|(k, v)| (k.clone(), resolve_all(v, variables)))
                .collect::<HashMap<String, String>>()
        });

        let resolved_body = req_rule.body.as_ref().map(|b| resolve_all(b, variables));

        tracing::trace!(
            target = %target_url,
            method = %req_rule.method,
            url = %full_url,
            headers = ?resolved_headers,
            body = ?resolved_body,
            "Prepared raw HTTP request payload"
        );

        tracing::debug!(target = %target_url, method = %req_rule.method, url = %full_url, "Sending HTTP request");
        
        // TODO: Pass follow_redirects to client if supported, for now just trace it
        if let Some(follow) = req_rule.follow_redirects {
            tracing::trace!("Template specified follow_redirects: {}", follow);
        }

        let resp = match client
            .send_request(
                &req_rule.method,
                &full_url,
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

        if !req_rule.extractors.is_empty() {
            let extracted = extract_from_response(
                &req_rule.extractors,
                &body_bytes,
                &resp_headers,
            );
            for (key, value) in extracted {
                variables.insert(key, value);
            }
        }

        tracing::debug!(status = %status, response_len = %body_bytes.len(), "Evaluating matchers");
        
        let matchers_succeeded = if req_rule.matchers.is_empty() {
            false
        } else {
            let is_or = req_rule.matcher_condition.eq_ignore_ascii_case("or");
            
            if is_or {
                req_rule.matchers.iter().any(|matcher| matches_condition(matcher, &body_bytes, &resp_headers, status))
            } else {
                req_rule.matchers.iter().all(|matcher| matches_condition(matcher, &body_bytes, &resp_headers, status))
            }
        };

        if matchers_succeeded {
            tracing::debug!("Vulnerability match found for template {} on {}", template_id, full_url);
            findings.push(ScanResult {
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: template_info.severity.clone(),
                target: target_url.to_string(),
                payload: resolved_path,
                cvss_score: None,
                reference: None,
                solution: None,
                tags: Vec::new(),
                compliance: Default::default(),
            });
        }
    }

    findings
}
