use crate::core::result::ScanResult;
use crate::network::http::StealthHttpClient;
use crate::template::schema::TemplateInfo;
use super::parser::CtLogAuditTemplate;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::HashMap;
use tracing::{debug, warn};

/// A single certificate entry from crt.sh API response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
struct CertificateEntry {
    id: Option<i64>,
    issuer_ca_id: Option<i64>,
    issuer_name: Option<String>,
    common_name: Option<String>,
    name_value: Option<String>,
    serial_number: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
    entry_timestamp: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    x509: Option<serde_json::Value>,
}

/// Classification of a certificate entry's risk.
#[derive(Debug, PartialEq)]
enum CertFinding {
    /// Unexpected subdomain for the target domain.
    UnexpectedSubdomain {
        subdomain: String,
        issued_at: String,
    },
    /// Wildcard certificate that could be used for subdomain takeover.
    WildcardCert {
        wildcard: String,
        issuer: String,
    },
    /// High velocity of certificate issuance (possible domain validation bypass).
    HighIssuanceVelocity {
        count: usize,
        window_hours: i64,
    },
    /// Recently issued certificate.
    RecentCert {
        common_name: String,
        not_before: String,
    },
    /// Certificates from unexpected or lesser-known CAs.
    UnexpectedCA {
        ca: String,
        common_name: String,
    },
    /// Self-signed or suspicious issuer.
    SuspiciousIssuer {
        issuer: String,
        common_name: String,
    },
}

const MAX_CERT_ENTRIES: usize = 500;

/// Parse the `not_before` field from crt.sh format ("YYYY-MM-DDTHH:MM:SS.mmm" or similar)
/// into a `DateTime<Utc>`.
fn parse_ct_date(date_str: &str) -> Option<DateTime<Utc>> {
    // Try multiple format patterns
    let patterns = &[
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d",
    ];

    for pattern in patterns {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(
            date_str.trim_end_matches("Z").trim_end_matches('z'),
            pattern,
        ) {
            return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
        }
        // Try as date-only
        if let Ok(d) = chrono::NaiveDate::parse_from_str(date_str.trim(), pattern) {
            let dt = d.and_hms_opt(0, 0, 0)?;
            return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
        }
    }
    None
}

/// Analyze certificate entries and return a list of findings.
fn analyze_certificates(
    entries: &[CertificateEntry],
    query_domain: &str,
) -> Vec<CertFinding> {
    let mut findings = Vec::new();

    if entries.is_empty() {
        return findings;
    }

    // --- 1. Check for wildcard certificates ---
    for entry in entries {
        if let Some(ref name_value) = entry.name_value {
            for name in name_value.split('\n') {
                let name = name.trim();
                if name.starts_with("*.") {
                    let issuer = entry
                        .issuer_name
                        .as_deref()
                        .unwrap_or("Unknown CA")
                        .to_string();
                    findings.push(CertFinding::WildcardCert {
                        wildcard: name.to_string(),
                        issuer,
                    });
                }
            }
        }
    }

    // --- 2. Check for unexpected subdomains ---
    // Collect unique subdomains that are not the root domain itself.
    let mut unexpected_subdomains: HashMap<String, String> = HashMap::new();
    for entry in entries {
        if let Some(ref name_value) = entry.name_value {
            for name in name_value.split('\n') {
                let name = name.trim().to_ascii_lowercase();
                let not_before = entry.not_before.as_deref().unwrap_or("unknown").to_string();
                if name != query_domain
                    && name.ends_with(&format!(".{}", query_domain))
                    && !name.starts_with('*')
                {
                    // Only record the earliest issuance date for each subdomain
                    unexpected_subdomains
                        .entry(name)
                        .or_insert(not_before);
                }
            }
        }
    }
    for (subdomain, issued_at) in &unexpected_subdomains {
        findings.push(CertFinding::UnexpectedSubdomain {
            subdomain: subdomain.clone(),
            issued_at: issued_at.clone(),
        });
    }

    // --- 3. Check issuance velocity ---
    // If many certificates were issued in a short window, it may indicate
    // domain validation abuse.
    let timestamps: Vec<DateTime<Utc>> = entries
        .iter()
        .filter_map(|e| {
            e.not_before
                .as_deref()
                .and_then(|s| parse_ct_date(s))
        })
        .collect();

    if timestamps.len() > 1 {
        let min_ts = timestamps.iter().min().copied().unwrap_or(Utc::now());
        let max_ts = timestamps.iter().max().copied().unwrap_or(Utc::now());
        let window_hours = (max_ts - min_ts).num_hours().max(1);
        let count = timestamps.len();

        // More than 10 certs in a 24-hour window is suspicious
        if count >= 10 && window_hours <= 48 {
            findings.push(CertFinding::HighIssuanceVelocity {
                count,
                window_hours,
            });
        }
    }

    // --- 4. Check for recently issued certificates (within last 7 days) ---
    let seven_days_ago = Utc::now() - chrono::Duration::days(7);
    for entry in entries {
        if let Some(ref not_before) = entry.not_before {
            if let Some(dt) = parse_ct_date(not_before) {
                if dt > seven_days_ago {
                    let cn = entry
                        .common_name
                        .as_deref()
                        .unwrap_or("unknown")
                        .to_string();
                    findings.push(CertFinding::RecentCert {
                        common_name: cn,
                        not_before: not_before.clone(),
                    });
                    // Limit to avoid noise
                    if findings
                        .iter()
                        .filter(|f| matches!(f, CertFinding::RecentCert { .. }))
                        .count()
                        >= 5
                    {
                        break;
                    }
                }
            }
        }
    }

    // --- 5. Check for unexpected / suspicious CAs ---
    let trusted_ca_keywords = &[
        "Let's Encrypt",
        "DigiCert",
        "GlobalSign",
        "Sectigo",
        "Comodo",
        "GoDaddy",
        "Amazon",
        "Google Trust",
        "Microsoft",
        "CloudFlare",
        "ZeroSSL",
        "Buypass",
        "Certum",
        "Entrust",
        "GeoTrust",
        "RapidSSL",
        "Thawte",
        "VeriSign",
    ];

    for entry in entries {
        if let Some(ref issuer) = entry.issuer_name {
            let issuer_lower = issuer.to_ascii_lowercase();
            let is_known_ca = trusted_ca_keywords
                .iter()
                .any(|known| issuer_lower.contains(&known.to_ascii_lowercase()));

            if !is_known_ca && !issuer_lower.contains("self-signed") {
                let cn = entry
                    .common_name
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_string();
                findings.push(CertFinding::UnexpectedCA {
                    ca: issuer.clone(),
                    common_name: cn,
                });
            }

            // Self-signed certificates for non-test domains are suspicious
            if issuer_lower.contains("self-signed") || issuer_lower.contains("localhost") {
                let cn = entry
                    .common_name
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_string();
                if !cn.contains("test") && !cn.contains("local") {
                    findings.push(CertFinding::SuspiciousIssuer {
                        issuer: issuer.clone(),
                        common_name: cn,
                    });
                }
            }
        }
    }

    findings
}

/// Build a human-readable payload from a list of findings.
fn findings_to_payload(findings: &[CertFinding]) -> (String, u8) {
    if findings.is_empty() {
        return ("No notable certificates found.".to_string(), 0);
    }

    let mut lines: Vec<String> = Vec::new();
    let mut severity_score: u8 = 0;

    for finding in findings {
        match finding {
            CertFinding::WildcardCert { wildcard, issuer } => {
                lines.push(format!(
                    "Wildcard certificate '{}' issued by '{}' - may allow subdomain takeover.",
                    wildcard, issuer
                ));
                severity_score = severity_score.saturating_add(15);
            }
            CertFinding::UnexpectedSubdomain {
                subdomain,
                issued_at,
            } => {
                lines.push(format!(
                    "Discovered subdomain '{}' (issued: {}) via CT logs.",
                    subdomain, issued_at
                ));
                severity_score = severity_score.saturating_add(5);
            }
            CertFinding::HighIssuanceVelocity { count, window_hours } => {
                lines.push(format!(
                    "High certificate issuance velocity: {} certificates in {} hour(s) - possible domain validation bypass.",
                    count, window_hours
                ));
                severity_score = severity_score.saturating_add(30);
            }
            CertFinding::RecentCert {
                common_name,
                not_before,
            } => {
                lines.push(format!(
                    "Recently issued certificate for '{}' on {} - review for legitimacy.",
                    common_name, not_before
                ));
                severity_score = severity_score.saturating_add(8);
            }
            CertFinding::UnexpectedCA { ca, common_name } => {
                lines.push(format!(
                    "Certificate for '{}' issued by unexpected CA '{}'.",
                    common_name, ca
                ));
                severity_score = severity_score.saturating_add(10);
            }
            CertFinding::SuspiciousIssuer { issuer, common_name } => {
                lines.push(format!(
                    "Suspicious issuer '{}' for certificate '{}'.",
                    issuer, common_name
                ));
                severity_score = severity_score.saturating_add(25);
            }
        }
    }

    (lines.join("\n"), severity_score.min(100))
}

/// Determine severity string from numeric score.
fn score_to_severity(score: u8) -> &'static str {
    match score {
        0 => "Info",
        1..=20 => "Low",
        21..=50 => "Medium",
        51..=75 => "High",
        76..=100 => "Critical",
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Execute Certificate Transparency log audit against a target domain.
///
/// Queries crt.sh for certificate entries, analyzes them for:
/// - Unexpected subdomains
/// - Wildcard certificates
/// - High issuance velocity
/// - Recently issued certificates
/// - Suspicious Certificate Authorities
pub async fn execute(
    templates: &[CtLogAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
    client: &StealthHttpClient,
) -> Option<ScanResult> {
    for template in templates {
        let query_domain = template.query_domain.trim().to_ascii_lowercase();
        let crt_sh_url = format!(
            "https://crt.sh/?q=%.{}&output=json&limit={}",
            query_domain, MAX_CERT_ENTRIES
        );

        debug!(domain = %query_domain, url = %crt_sh_url, "Querying crt.sh");

        let resp = match client
            .send_request("GET", &crt_sh_url, None, None)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    domain = %query_domain,
                    error = %e,
                    "Failed to query crt.sh"
                );
                continue;
            }
        };

        if !resp.status().is_success() {
            warn!(
                domain = %query_domain,
                status = %resp.status(),
                "crt.sh returned non-success status"
            );
            continue;
        }

        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    domain = %query_domain,
                    error = %e,
                    "Failed to read crt.sh response body"
                );
                continue;
            }
        };

        // crt.sh returns an empty response or "null" when no entries are found
        if body.trim().is_empty() || body.trim() == "null" {
            debug!(domain = %query_domain, "No CT log entries found");
            return None;
        }

        let entries: Vec<CertificateEntry> = match serde_json::from_str(&body) {
            Ok(e) => e,
            Err(e) => {
                warn!(
                    domain = %query_domain,
                    error = %e,
                    "Failed to parse crt.sh JSON response"
                );
                continue;
            }
        };

        if entries.is_empty() {
            debug!(domain = %query_domain, "Empty CT log entries array");
            return None;
        }

        debug!(
            domain = %query_domain,
            entry_count = entries.len(),
            "Parsed CT log entries"
        );

        // Analyze the fetched certificates
        let findings = analyze_certificates(&entries, &query_domain);

        if findings.is_empty() {
            // No notable findings — return Info-level result anyway to indicate
            // the domain was checked
            let mut compliance = HashMap::new();
            compliance.insert("recon".to_string(), "OSINT".to_string());

            return Some(ScanResult {
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: "Info".to_string(),
                target: query_domain.clone(),
                payload: format!(
                    "Certificate Transparency audit completed for '{}'. {} certificate(s) found, no suspicious patterns detected.",
                    query_domain,
                    entries.len()
                ),
                cvss_score: None,
                reference: Some("https://crt.sh/".to_string()),
                solution: None,
                tags: vec![
                    "ct-log".to_string(),
                    "certificate".to_string(),
                    "osint".to_string(),
                ],
                compliance,
            });
        }

        let (payload, severity_score) = findings_to_payload(&findings);
        let severity = score_to_severity(severity_score);
        let cvss = (severity_score as f32) / 10.0;

        let mut compliance = HashMap::new();
        compliance.insert("recon".to_string(), "OSINT".to_string());
        compliance.insert(
            "standard".to_string(),
            "CA/Browser Forum Baseline Requirements".to_string(),
        );

        // Build tags based on finding types
        let mut tags: Vec<String> = vec![
            "ct-log".to_string(),
            "certificate".to_string(),
            "osint".to_string(),
        ];
        for finding in &findings {
            match finding {
                CertFinding::WildcardCert { .. } => {
                    tags.push("wildcard".to_string());
                }
                CertFinding::UnexpectedSubdomain { .. } => {
                    tags.push("subdomain".to_string());
                }
                CertFinding::HighIssuanceVelocity { .. } => {
                    tags.push("velocity".to_string());
                }
                CertFinding::RecentCert { .. } => {
                    tags.push("recent".to_string());
                }
                CertFinding::UnexpectedCA { .. } | CertFinding::SuspiciousIssuer { .. } => {
                    tags.push("suspicious-ca".to_string());
                }
            }
        }

        let count_unexpected = findings
            .iter()
            .filter(|f| matches!(f, CertFinding::UnexpectedSubdomain { .. }))
            .count();

        let technical_details = format!(
            "Analyzed {} certificate(s) from crt.sh. Found {} finding(s) including {} unexpected subdomain(s).",
            entries.len(),
            findings.len(),
            count_unexpected,
        );

        let final_payload = format!("{}\n\n{}", payload, technical_details);

        return Some(ScanResult {
            timestamp: Utc::now(),
            template_id: template_id.to_string(),
            template_name: template_info.name.clone(),
            template_severity: severity.to_string(),
            target: query_domain.clone(),
            payload: final_payload,
            cvss_score: Some(cvss),
            reference: Some("https://crt.sh/ | https://letsencrypt.org/docs/ct-logs/".to_string()),
            solution: Some(
                "Review certificate issuance for unauthorized subdomains. \
                 Consider using CAA DNS records to restrict which CAs can issue \
                 certificates for your domain. Monitor CT logs regularly for unexpected certificates."
                    .to_string(),
            ),
            tags,
            compliance,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ct_date_standard() {
        let result = parse_ct_date("2023-01-15T10:30:00");
        assert!(result.is_some());
        let dt = result.unwrap();
        assert_eq!(dt.year(), 2023);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 15);
    }

    #[test]
    fn test_parse_ct_date_date_only() {
        let result = parse_ct_date("2023-01-15");
        assert!(result.is_some());
        let dt = result.unwrap();
        assert_eq!(dt.year(), 2023);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 15);
    }

    #[test]
    fn test_score_to_severity() {
        assert_eq!(score_to_severity(0), "Info");
        assert_eq!(score_to_severity(10), "Low");
        assert_eq!(score_to_severity(30), "Medium");
        assert_eq!(score_to_severity(60), "High");
        assert_eq!(score_to_severity(90), "Critical");
    }

    #[test]
    fn test_analyze_certificates_wildcard() {
        let entries = vec![CertificateEntry {
            id: Some(1),
            issuer_ca_id: Some(999),
            issuer_name: Some("Let's Encrypt".to_string()),
            common_name: Some("*.example.com".to_string()),
            name_value: Some("*.example.com".to_string()),
            serial_number: None,
            not_before: Some("2023-01-01T00:00:00".to_string()),
            not_after: Some("2024-01-01T00:00:00".to_string()),
            entry_timestamp: None,
            x509: None,
        }];

        let findings = analyze_certificates(&entries, "example.com");
        assert!(findings.iter().any(|f| matches!(f, CertFinding::WildcardCert { .. })));
    }

    #[test]
    fn test_analyze_certificates_subdomain() {
        let entries = vec![CertificateEntry {
            id: Some(2),
            issuer_ca_id: Some(1),
            issuer_name: Some("Let's Encrypt".to_string()),
            common_name: Some("admin.example.com".to_string()),
            name_value: Some("admin.example.com".to_string()),
            serial_number: None,
            not_before: Some("2023-06-01T00:00:00".to_string()),
            not_after: Some("2024-06-01T00:00:00".to_string()),
            entry_timestamp: None,
            x509: None,
        }];

        let findings = analyze_certificates(&entries, "example.com");
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, CertFinding::UnexpectedSubdomain { subdomain, .. } if subdomain == "admin.example.com"))
        );
    }
}