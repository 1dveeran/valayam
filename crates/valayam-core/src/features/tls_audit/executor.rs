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
/// - `type: "weak_cipher"` — matches if the negotiated cipher is weak (e.g., CBC)
/// - `type: "tls_version"` — regex match against the negotiated TLS version
/// - `type: "legacy_tls"` — active probe to see if server supports SSLv3, TLSv1.0, TLSv1.1
/// - `type: "regex"` — regex match against issuer, subject, serial, version, or cipher
pub async fn execute(
    tls_rules: &[TlsAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
    variables: &HashMap<String, String>,
) -> Option<ScanResult> {
    for rule in tls_rules {
        let host = resolve_variables(&rule.host, variables);

        tracing::debug!(target = %host, port = %rule.port, "Starting TLS certificate inspection");
        
        let mut cert_info = None;
        let mut legacy_versions = Vec::new();

        let needs_legacy_probe = rule.matchers.iter().any(|m| m.r#type == "legacy_tls");
        if needs_legacy_probe {
            legacy_versions = tls::probe_legacy_tls(&host, rule.port).await;
        }

        let needs_cert_inspection = rule.matchers.is_empty() || rule.matchers.iter().any(|m| m.r#type != "legacy_tls");
        if needs_cert_inspection {
            cert_info = tls::inspect_certificate(&host, rule.port).await;
        }

        if cert_info.is_none() && legacy_versions.is_empty() {
            tracing::trace!(target = %host, port = %rule.port, "Failed to connect or extract TLS information");
            continue;
        }

        if rule.matchers.is_empty() {
            if let Some(c) = cert_info {
                return Some(ScanResult {
                    timestamp: Utc::now(),
                    template_id: template_id.to_string(),
                    template_name: template_info.name.clone(),
                    template_severity: template_info.severity.clone(),
                    target: format!("{}:{}", host, rule.port),
                    payload: format!(
                        "Issuer: {}, Subject: {}, Expires: {}, Self-signed: {}",
                        c.issuer, c.subject, c.not_after, c.is_self_signed
                    ),
                });
            }
        }

        for matcher in &rule.matchers {
            let matched = match matcher.r#type.as_str() {
                "legacy_tls" => !legacy_versions.is_empty(),
                "expired" => cert_info.as_ref().map_or(false, |c| c.is_expired),
                "self_signed" => cert_info.as_ref().map_or(false, |c| c.is_self_signed),
                "weak_cipher" => {
                    cert_info.as_ref().and_then(|c| c.cipher_suite.as_ref()).map_or(false, |cipher| {
                        cipher.contains("CBC") || cipher.contains("RC4") || cipher.contains("3DES") || cipher.contains("DES")
                    })
                },
                "tls_version" => {
                    cert_info.as_ref().and_then(|c| c.tls_version.as_ref()).map_or(false, |v| {
                        matcher.regex.iter().any(|pattern| {
                            Regex::new(pattern).map(|re| re.is_match(v)).unwrap_or(false)
                        })
                    })
                },
                "regex" => {
                    if let Some(c) = cert_info.as_ref() {
                        let search_text = match matcher.part.as_str() {
                            "issuer" => &c.issuer,
                            "subject" => &c.subject,
                            "serial" => &c.serial,
                            "version" => c.tls_version.as_deref().unwrap_or(""),
                            "cipher" => c.cipher_suite.as_deref().unwrap_or(""),
                            _ => &c.issuer,
                        };
                        matcher.regex.iter().any(|pattern| {
                            Regex::new(pattern)
                                .map(|re| re.is_match(search_text))
                                .unwrap_or(false)
                        })
                    } else {
                        false
                    }
                }
                _ => false,
            };

            if matched {
                tracing::debug!(target = %host, matcher_type = %matcher.r#type, "Vulnerability TLS match found");
                let payload = match matcher.r#type.as_str() {
                    "expired" => format!("Certificate expired: {}", cert_info.as_ref().unwrap().not_after),
                    "self_signed" => "Self-signed certificate detected".to_string(),
                    "weak_cipher" => format!("Weak cipher negotiated: {}", cert_info.as_ref().unwrap().cipher_suite.as_deref().unwrap_or("Unknown")),
                    "tls_version" => format!("TLS version matched: {}", cert_info.as_ref().unwrap().tls_version.as_deref().unwrap_or("Unknown")),
                    "legacy_tls" => format!("Legacy protocols supported: {:?}", legacy_versions),
                    _ => format!(
                        "TLS match on {}: issuer={}, expires={}",
                        host, 
                        cert_info.as_ref().map(|c| c.issuer.as_str()).unwrap_or(""), 
                        cert_info.as_ref().map(|c| c.not_after.as_str()).unwrap_or("")
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
