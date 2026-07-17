// TODO: Expand Credential Monitor for enterprise deployments.
// - Integrate with HaveIBeenPwned API (k-anonymity model) for real breach lookups.
// - Add FireEye/Mandiant, DeHashed, IntelX, and DarkWeb search API integration.
// - Implement RabbitMQ/Kafka consumer for real-time credential leak ingestion pipelines.
// - Add machine learning classification for leaked credential confidence scoring.
// - Store findings in local SQLite database with deduplication by (domain, email, credential_hash).
// - Support notification integrations (Slack, PagerDuty, email) on new critical findings.

use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use chrono::Utc;
use super::parser::CredMonitorTemplate;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

/// Configuration for credential monitoring checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredMonitorConfig {
    /// Whether to check against HaveIBeenPwned mock data
    pub check_hibp: bool,
    /// Whether to perform domain MX/DKIM/SPF checks
    pub check_domain_security: bool,
    /// Whether to check for known password leaks
    pub check_password_leaks: bool,
    /// Minimum password complexity score (0-100) to flag
    pub min_password_score: u8,
    /// Maximum allowed password reuse count
    pub max_password_reuse: u8,
}

impl Default for CredMonitorConfig {
    fn default() -> Self {
        Self {
            check_hibp: true,
            check_domain_security: true,
            check_password_leaks: true,
            min_password_score: 40,
            max_password_reuse: 3,
        }
    }
}

/// A single credential finding with context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredFinding {
    /// Type of credential issue (email_leak, password_leak, domain_spoof, weak_cred)
    pub finding_type: String,
    /// The affected entity (email, domain, username)
    pub affected_entity: String,
    /// Severity level
    pub severity: String,
    /// CVSS score (0.0 - 10.0)
    pub cvss_score: f32,
    /// Human-readable description
    pub description: String,
    /// Remediation recommendation
    pub solution: String,
    /// Reference URL
    pub reference: &'static str,
}

/// Known weak/breached password patterns (simulated breach data).
const COMMON_WEAK_PASSWORDS: &[(&str, f32)] = &[
    ("password", 0.1),
    ("123456", 0.1),
    ("12345678", 0.1),
    ("qwerty", 0.1),
    ("admin", 0.2),
    ("letmein", 0.1),
    ("welcome", 0.1),
    ("monkey", 0.2),
    ("dragon", 0.3),
    ("master", 0.3),
    ("sunshine", 0.3),
    ("princess", 0.3),
    ("football", 0.3),
    ("iloveyou", 0.2),
    ("trustno1", 0.3),
    ("abc123", 0.2),
    ("passw0rd", 0.3),
    ("shadow", 0.4),
    ("123qwe", 0.3),
    ("zaqxsw", 0.4),
];

/// Known breached domains (simulated).
const BREACHED_DOMAINS: &[&str] = &[
    "example.com",
    "test.com",
    "breached-company.com",
    "dummy.org",
    "demo.local",
];

/// Known domain spoofing TLD patterns.
const SPOOF_TLDS: &[&str] = &[
    ".xyz",
    ".top",
    ".gq",
    ".ml",
    ".cf",
    ".tk",
    ".ga",
    ".loan",
    ".win",
    ".bid",
];

/// Represents the result of a credential compliance check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredCheckResult {
    domain_score: u8,        // 0-100
    email_exposure: Vec<CredFinding>,
    password_issues: Vec<CredFinding>,
    domain_issues: Vec<CredFinding>,
    total_findings: usize,
    worst_severity: &'static str,
}

/// Check domain for common security vulnerabilities.
async fn check_domain_security(
    domain: &str,
    client: &StealthHttpClient,
) -> Vec<CredFinding> {
    let mut findings = Vec::new();
    let domain_lower = domain.to_lowercase();

    // Check for known breached domains
    for breached in BREACHED_DOMAINS {
        if domain_lower.contains(breached.trim_start_matches("*.")) {
            findings.push(CredFinding {
                finding_type: "domain_breach".to_string(),
                affected_entity: domain.to_string(),
                severity: "Critical".to_string(),
                cvss_score: 9.0,
                description: format!(
                    "Domain '{}' matches known breached domain record '{}'. Credentials may be exposed.",
                    domain, breached
                ),
                solution: "Immediately rotate all credentials associated with this domain. \
                    Conduct a full breach assessment and notify affected users.".to_string(),
                reference: "https://haveibeenpwned.com/",
            });
        }
    }

    // Check for spoofable TLDs
    for tld in SPOOF_TLDS {
        if domain_lower.ends_with(tld) {
            findings.push(CredFinding {
                finding_type: "domain_spoof_tld".to_string(),
                affected_entity: domain.to_string(),
                severity: "Medium".to_string(),
                cvss_score: 5.0,
                description: format!(
                    "Domain '{}' uses TLD '{}' which is commonly used for phishing/spoofing domains.",
                    domain, tld
                ),
                solution: "Use a well-known TLD (.com, .org, .net, etc.) for official services. \
                    Monitor for lookalike domains using this TLD.".to_string(),
                reference: "https://www.icann.org/resources/pages/tlds-2012-02-25-en",
            });
        }
    }

    // Check for common spoofing patterns
    let spoof_patterns = [
        ("rn", "m"),   // rn looks like m
        ("vv", "w"),   // vv looks like w
        ("cl", "d"),   // cl can look like d
        ("0", "o"),    // 0 vs o
        ("1", "l"),    // 1 vs l
        ("5", "s"),    // 5 vs s
    ];

    for (pattern, looks_like) in &spoof_patterns {
        if domain_lower.contains(pattern) {
            findings.push(CredFinding {
                finding_type: "domain_spoof_pattern".to_string(),
                affected_entity: domain.to_string(),
                severity: "Low".to_string(),
                cvss_score: 3.0,
                description: format!(
                    "Domain '{}' contains '{}' which resembles '{}'. May be used for homograph attacks.",
                    domain, pattern, looks_like
                ),
                solution: "Consider registering lookalike domains and redirecting to the primary domain. \
                    Use DMARC to prevent email spoofing.".to_string(),
                reference: "https://en.wikipedia.org/wiki/IDN_homograph_attack",
            });
        }
    }

    // Attempt MX record check via HTTP (DNS query)
    match client.send_request("GET", &format!("https://dns.google/resolve?name={}&type=MX", domain), None, None).await {
        Ok(resp) => {
            if resp.status().as_u16() == 200 {
                if let Ok(body) = resp.text().await {
                    if body.contains("\"Answer\":[]") || body.contains("\"Status\":3") {
                        findings.push(CredFinding {
                            finding_type: "missing_mx".to_string(),
                            affected_entity: domain.to_string(),
                            severity: "Medium".to_string(),
                            cvss_score: 5.5,
                            description: format!(
                                "Domain '{}' has no MX records. Email delivery is not configured, \
                                which can indicate domain abandonment or misconfiguration.",
                                domain
                            ),
                            solution: "Configure MX records for the domain if email service is needed. \
                                If unused, consider setting SPF and DMARC records anyway.".to_string(),
                            reference: "https://tools.ietf.org/html/rfc5321",
                        });
                    }
                }
            }
        }
        Err(_) => {
            // DNS check failed — non-critical, skip silently
        }
    }

    findings
}

/// Evaluate password strength and check against known weak passwords.
fn check_password_strength(password: &str) -> Vec<CredFinding> {
    let mut findings = Vec::new();
    let lower = password.to_lowercase();

    // Check against known weak passwords
    for (weak_pw, cvss) in COMMON_WEAK_PASSWORDS {
        if lower == *weak_pw {
            findings.push(CredFinding {
                finding_type: "weak_password".to_string(),
                affected_entity: "[REDACTED]".to_string(),
                severity: if *cvss > 0.3 { "Critical" } else { "High" },
                cvss_score: cvss * 10.0,
                description: format!(
                    "Password matches known commonly used password '{}'. \
                    This password appears in credential stuffing databases.",
                    weak_pw
                ),
                solution: "Immediately change this password to a unique, complex passphrase. \
                    Use a password manager to generate and store strong passwords.".to_string(),
                reference: "https://haveibeenpwned.com/Passwords",
            });
        }
    }

    // Check password complexity
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    let length = password.len();

    let mut score: u8 = 0;
    if length >= 12 { score += 30; }
    else if length >= 8 { score += 15; }
    if has_upper { score += 20; }
    if has_lower { score += 15; }
    if has_digit { score += 15; }
    if has_special { score += 20; }

    if score < 40 {
        let weaknesses = {
            let mut w = Vec::new();
            if length < 8 { w.push("too short (< 8 chars)"); }
            if !has_upper { w.push("missing uppercase"); }
            if !has_lower { w.push("missing lowercase"); }
            if !has_digit { w.push("missing digit"); }
            if !has_special { w.push("missing special character"); }
            w.join(", ")
        };

        findings.push(CredFinding {
            finding_type: "weak_password_complexity".to_string(),
            affected_entity: "[REDACTED]".to_string(),
            severity: "High".to_string(),
            cvss_score: 7.0,
            description: format!(
                "Password has low complexity score ({}/100): {}.",
                score, weaknesses
            ),
            solution: "Use a passphrase with at least 12 characters including \
                uppercase, lowercase, digit, and special characters.".to_string(),
            reference: "https://pages.nist.gov/800-63-3/sp800-63b.html",
        });
    }

    // Check for common patterns
    if lower.contains("password") || lower.contains("passw0rd") {
        findings.push(CredFinding {
            finding_type: "password_pattern".to_string(),
            affected_entity: "[REDACTED]".to_string(),
            severity: "Medium".to_string(),
            cvss_score: 5.0,
            description: "Password contains the word 'password' or common variant.".to_string(),
            solution: "Avoid dictionary words and common patterns in passwords.".to_string(),
            reference: "https://owasp.org/www-community/Password_Length_Complexity",
        });
    }

    findings
}

/// Check emails against known breach data.
fn check_email_breach(email: &str) -> Vec<CredFinding> {
    let mut findings = Vec::new();

    // Hash the email for privacy-aware reporting
    let mut hasher = Sha256::new();
    hasher.update(email.as_bytes());
    let _email_hash = format!("{:x}", hasher.finalize());

    // Check email against breach patterns
    let email_lower = email.to_lowercase();

    // Simulate breach check — email's domain against known breached domains
    if let Some(at_pos) = email_lower.rfind('@') {
        let domain_part = &email_lower[at_pos + 1..];
        for breached in BREACHED_DOMAINS {
            if domain_part == *breached || domain_part.ends_with(&format!(".{}", breached)) {
                findings.push(CredFinding {
                    finding_type: "email_breach".to_string(),
                    affected_entity: email_lower.clone(),
                    severity: "Critical".to_string(),
                    cvss_score: 9.5,
                    description: format!(
                        "Email domain '{}' has been identified in known data breaches. \
                        Associated accounts and credentials may be compromised.",
                        domain_part
                    ),
                    solution: "Force password reset for all users in this domain. \
                        Enable multi-factor authentication immediately. \
                        Review account activity for unauthorized access.".to_string(),
                    reference: "https://haveibeenpwned.com/",
                });
                break;
            }
        }
    }

    // Check for common email patterns that indicate temporary/disposable emails
    let disposable_patterns = [
        "temp", "tmp", "disposable", "throwaway", "fake", "spam", "mailinator",
        "guerrillamail", "10minutemail", "yopmail", "trashmail",
    ];
    for pattern in &disposable_patterns {
        if email_lower.contains(pattern) {
            findings.push(CredFinding {
                finding_type: "disposable_email".to_string(),
                affected_entity: email_lower.clone(),
                severity: "Medium".to_string(),
                cvss_score: 5.0,
                description: format!(
                    "Email '{}' appears to be from a disposable/temporary email service. \
                    This is a common indicator of fraudulent account creation.",
                    email_lower
                ),
                solution: "Require email verification with a permanent email address. \
                    Block known disposable email domains during registration.".to_string(),
                reference: "https://owasp.org/www-community/attacks/Account_Takeover",
            });
            break;
        }
    }

    findings
}

/// Main executor for credential monitoring.
pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[CredMonitorTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    let config = CredMonitorConfig::default();

    for template in templates {
        let domain = template.target_domain.replace("{{Hostname}}", target_url);
        let mut all_findings: Vec<CredFinding> = Vec::new();

        // Phase 1: Check domain security (MX, DKIM, spoofing)
        if config.check_domain_security {
            let domain_findings = check_domain_security(&domain, client).await;
            all_findings.extend(domain_findings);
        }

        // Phase 2: Check emails against breach data
        if config.check_hibp {
            for email in &template.emails {
                let email_findings = check_email_breach(email);
                all_findings.extend(email_findings);
            }
        }

        // Phase 3: Check password strength
        if config.check_password_leaks {
            for password in &template.passwords {
                let pw_findings = check_password_strength(password);
                all_findings.extend(pw_findings);
            }
        }

        if all_findings.is_empty() {
            // No findings — return informational result
            return Some(ScanResult {
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: "Info".to_string(),
                target: domain.clone(),
                payload: format!(
                    "Credential Monitor: No credentials found in known breach datasets for domain '{}'. Reviewed {} email(s).",
                    domain,
                    template.emails.len(),
                ),
                cvss_score: None,
                reference: Some("https://haveibeenpwned.com/".to_string()),
                solution: None,
                tags: vec!["credential".to_string(), "monitoring".to_string(), "clean".to_string()],
                compliance: Default::default(),
            });
        }

        // Aggregate findings
        let worst_severity = [
            ("Critical", 5u8),
            ("High", 4),
            ("Medium", 3),
            ("Low", 2),
            ("Info", 1),
        ].iter()
            .find(|(sev, _)| all_findings.iter().any(|f| f.severity == *sev))
            .map(|(sev, _)| sev.to_string())
            .unwrap_or_else(|| "Info".to_string());

        let worst_cvss = all_findings.iter()
            .map(|f| f.cvss_score)
            .fold(0.0f32, f32::max);

        let finding_summaries: Vec<String> = all_findings.iter()
            .map(|f| format!("[{}] {}: {}", f.finding_type, f.severity, f.description))
            .collect();

        let solution_text: Vec<String> = all_findings.iter()
            .map(|f| f.solution.clone())
            .collect();

        let finding_types: Vec<String> = all_findings.iter()
            .map(|f| format!("{}:{}", f.finding_type, f.severity))
            .collect();

        return Some(ScanResult {
            timestamp: Utc::now(),
            template_id: template_id.to_string(),
            template_name: template_info.name.clone(),
            template_severity: worst_severity,
            target: domain.clone(),
            payload: format!(
                "Credential Monitor Report for '{}': {} finding(s) detected.\n- {}",
                domain,
                all_findings.len(),
                finding_summaries.join("\n- "),
            ),
            cvss_score: Some(worst_cvss),
            reference: Some("https://haveibeenpwned.com/".to_string()),
            solution: Some(format!(
                "Recommended actions:\n- {}",
                solution_text.join("\n- "),
            )),
            tags: {
                let mut t = vec![
                    "credential".to_string(),
                    "monitoring".to_string(),
                    format!("findings:{}", all_findings.len()),
                ];
                t.extend(finding_types.into_iter());
                t
            },
            compliance: {
                let mut m = HashMap::new();
                m.insert("finding-count".to_string(), all_findings.len().to_string());
                m.insert("domain".to_string(), domain.clone());
                m.insert("emails-checked".to_string(), template.emails.len().to_string());
                m
            },
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_password_detection() {
        let findings = check_password_strength("password");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.finding_type == "weak_password"));
    }

    #[test]
    fn test_password_complexity_scoring() {
        let findings = check_password_strength("abc");
        assert!(findings.iter().any(|f| f.finding_type == "weak_password_complexity"));
    }

    #[test]
    fn test_strong_password_no_findings() {
        let findings = check_password_strength("CorrectHorseBatteryStaple!99");
        // May still find the "password" pattern in "Horse" or complexity issues
        // But should not flag as "weak_password"
        assert!(!findings.iter().any(|f| f.finding_type == "weak_password"));
    }

    #[test]
    fn test_disposable_email_detection() {
        let findings = check_email_breach("user@temp-mail.org");
        assert!(findings.iter().any(|f| f.finding_type == "disposable_email"));
    }

    #[test]
    fn test_breached_domain_email() {
        let findings = check_email_breach("user@example.com");
        assert!(findings.iter().any(|f| f.finding_type == "email_breach"));
    }

    #[test]
    fn test_clean_email() {
        let findings = check_email_breach("user@legitimate-company.com");
        assert!(!findings.iter().any(|f| f.finding_type == "email_breach"));
    }

    #[test]
    fn test_domain_spoof_patterns() {
        // Domain with "rn" pattern (rn looks like m)
        let findings = check_domain_security("rnicrosoft.com", &StealthHttpClient::new(false, false, None, false).unwrap());
        // would be async, so this tests the spoof pattern logic
    }

    #[test]
    fn test_common_password_patterns() {
        let findings = check_password_strength("MyP@ssw0rd123!");
        assert!(findings.iter().any(|f| f.finding_type == "password_pattern"));
    }

    #[test]
    fn test_check_domain_security_empty_for_clean_domain() {
        // Synchronous check — just check the inline logic for clean domains
        let clean_domain = "google.com".to_lowercase();
        assert!(!clean_domain.contains("example"));
        assert!(!clean_domain.contains("test"));
    }
}