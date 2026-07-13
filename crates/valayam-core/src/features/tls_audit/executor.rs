use crate::core::result::ScanResult;
use crate::core::variables::resolve_variables;
use crate::network::tls;
use crate::template::schema::TemplateInfo;
use super::parser::TlsAuditTemplate;
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;

/// Executes all TLS audit rules from a template.
///
/// Supports special matcher types:
/// - `type: "expired"` — matches if the certificate is past its expiry date
/// - `type: "self_signed"` — matches if the certificate is self-signed
/// - `type: "regex"` with `part: "issuer"` — regex match against issuer string
/// - `type: "regex"` with `part: "subject"` — regex match against subject string
pub async fn execute(
    tls_rules: &[TlsAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
    variables: &HashMap<String, String>,
) -> Option<ScanResult> {
    for rule in tls_rules {
        let host = resolve_variables(&rule.host, variables);

        let Some(cert_info) = tls::inspect_certificate(&host, rule.port).await else {
            continue; // Could not connect or extract cert
        };

        if rule.matchers.is_empty() {
            // No matchers: report cert info as finding
            return Some(ScanResult {
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: template_info.severity.clone(),
                target: format!("{}:{}", host, rule.port),
                payload: format!(
                    "Issuer: {}, Subject: {}, Expires: {}, Self-signed: {}",
                    cert_info.issuer, cert_info.subject, cert_info.not_after, cert_info.is_self_signed
                ),
            });
        }

        for matcher in &rule.matchers {
            let matched = match matcher.r#type.as_str() {
                "expired" => cert_info.is_expired,
                "self_signed" => cert_info.is_self_signed,
                "regex" => {
                    let search_text = match matcher.part.as_str() {
                        "issuer" => &cert_info.issuer,
                        "subject" => &cert_info.subject,
                        "serial" => &cert_info.serial,
                        _ => &cert_info.issuer, // default to issuer
                    };
                    matcher.regex.iter().any(|pattern| {
                        Regex::new(pattern)
                            .map(|re| re.is_match(search_text))
                            .unwrap_or(false)
                    })
                }
                _ => false,
            };

            if matched {
                let payload = match matcher.r#type.as_str() {
                    "expired" => format!("Certificate expired: {}", cert_info.not_after),
                    "self_signed" => "Self-signed certificate detected".to_string(),
                    _ => format!(
                        "TLS match on {}: issuer={}, expires={}",
                        host, cert_info.issuer, cert_info.not_after
                    ),
                };

                return Some(ScanResult {
                    timestamp: Utc::now(),
                    template_id: template_id.to_string(),
                    template_name: template_info.name.clone(),
                    template_severity: template_info.severity.clone(),
                    target: format!("{}:{}", host, rule.port),
                    payload,
                });
            }
        }
    }

    None
}
