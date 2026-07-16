use crate::core::result::ScanResult;
use crate::core::variables::resolve_variables;
use crate::features::auth_logic::parser::{AuthTemplate, LogicTemplate};
use crate::network::http::StealthHttpClient;
use crate::template::schema::TemplateInfo;
use std::collections::HashMap;

/// Executes auth logic tests such as IDOR detection.
pub async fn execute(
    client: &StealthHttpClient,
    target_url: &str,
    logic: &[LogicTemplate],
    auth: &AuthTemplate,
    template_id: &str,
    template_info: &TemplateInfo,
    variables: &HashMap<String, String>,
) -> Option<ScanResult> {
    for l in logic {
        if l.r#type.to_lowercase() == "idor" {
            // Resolve primary and secondary auth headers
            let primary_auth = resolve_variables(&auth.primary, variables);
            let secondary_auth = resolve_variables(&auth.secondary, variables);
            let path = resolve_variables(&l.path, variables);
            let full_url = if path.starts_with("http") {
                path.clone()
            } else {
                format!("{}{}", target_url.trim_end_matches('/'), path)
            };

            // Step 1: Baseline request with primary auth
            let mut p_headers = HashMap::new();
            p_headers.insert("Authorization".to_string(), primary_auth.clone());
            
            let p_status = if let Ok(resp) = client.send_request(&l.method, &full_url, Some(&p_headers), None).await {
                resp.status().as_u16()
            } else {
                continue;
            };

            // Step 2: Attacker request with secondary auth
            let mut s_headers = HashMap::new();
            s_headers.insert("Authorization".to_string(), secondary_auth.clone());
            
            if let Ok(resp) = client.send_request(&l.method, &full_url, Some(&s_headers), None).await {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();

                // Step 3: Matcher Evaluation (Inline)
                let is_match = if l.matchers.is_empty() {
                    false
                } else {
                    l.matchers.iter().all(|matcher| {
                        if matcher.r#type == "regex" && matcher.part == "body" {
                            matcher.regex.iter().any(|r| {
                                if let Ok(re) = regex::Regex::new(r) {
                                    re.is_match(&body)
                                } else {
                                    false
                                }
                            })
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
                
                // If it matches our vulnerable conditions, and the baseline didn't fail
                if is_match && (p_status >= 200 && p_status < 400) {
                    return Some(ScanResult {
                        cvss_score: None,
                        reference: None,
                        solution: None,
                        timestamp: chrono::Utc::now(),
                        template_id: template_id.to_string(),
                        template_name: template_info.name.clone(),
                        template_severity: template_info.severity.clone(),
                        target: full_url.clone(),
                        payload: format!("IDOR Detected via token swapping on {} {}", l.method, path),
                        compliance: template_info.compliance.clone(),
                        tags: Vec::new(),
                    });
                }
            }
        }
    }

    // Secondary Check: Offline JWT Brute Forcing
    // Extract token from Bearer prefix if it exists
    let raw_token = auth.primary.trim_start_matches("Bearer ").trim();
    if raw_token.split('.').count() == 3 {
        // Looks like a JWT
        if let Some(cracked_secret) = super::jwt_cracker::JwtCracker::crack_jwt_secret(raw_token) {
            return Some(ScanResult {
                cvss_score: None,
                reference: None,
                solution: None,
                timestamp: chrono::Utc::now(),
                template_id: template_id.to_string(),
                template_name: format!("{} - Offline JWT Cracking", template_info.name),
                template_severity: "Critical".to_string(),
                target: target_url.to_string(),
                payload: format!("Successfully cracked JWT secret offline! The signing key is: '{}'", cracked_secret),
                compliance: template_info.compliance.clone(),
                tags: Vec::new(),
            });
        }
    }
    None
}
