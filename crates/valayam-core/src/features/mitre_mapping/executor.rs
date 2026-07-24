// TODO: Expand MITRE ATT&CK mapping for enterprise compliance.
// - Add tactic-level aggregation for kill-chain analysis.
// - Add platform-specific technique filtering (cloud, container, mobile).
// - Integrate with external ATT&CK TAXII feeds for real-time updates.
// - Add CVSS-to-MITRE severity correlation.

use valayam_models::finding::FindingOwned;
use valayam_models::{TemplateInfo, TemplateMetadata};
use valayam_models::templates::mitre_mapping::MitreMappingTemplate;
use lazy_static::lazy_static;
use std::collections::HashMap;

/// A single MITRE ATT&CK technique entry.
#[derive(Debug, Clone)]
pub struct MitreTechnique {
    pub technique_id: String,
    pub name: String,
    pub tactic: String,
    pub platform: &'static [&'static str],
    pub detection: &'static str,
}

// Lookup MITRE techniques by CWE ID or finding keyword.
lazy_static! {
    /// CWE-to-MITRE techniques mapping.
    /// Each CWE maps to one or more relevant MITRE ATT&CK techniques.
    static ref MITRE_MAP: HashMap<&'static str, Vec<MitreTechnique>> = {
        let mut m = HashMap::new();

        // ===== Web Application Security =====
        m.insert("CWE-79", vec![
            MitreTechnique { technique_id: "T1190".into(), name: "Exploit Public-Facing Application".into(), tactic: "Initial Access".into(), platform: &["Web", "SaaS"], detection: "WAF/IDS signatures, input validation logging" },
            MitreTechnique { technique_id: "T1059".into(), name: "Command and Scripting Interpreter".into(), tactic: "Execution".into(), platform: &["Windows", "Linux", "macOS"], detection: "Monitor script execution, AMSI" },
            MitreTechnique { technique_id: "T1189".into(), name: "Drive-by Compromise".into(), tactic: "Initial Access".into(), platform: &["Web"], detection: "Browser isolation, content security policies" },
        ]);

        m.insert("CWE-89", vec![
            MitreTechnique { technique_id: "T1190".into(), name: "Exploit Public-Facing Application".into(), tactic: "Initial Access".into(), platform: &["Web", "SaaS"], detection: "SQL injection detection signatures, parameterized query logging" },
            MitreTechnique { technique_id: "T1562".into(), name: "Impair Defenses".into(), tactic: "Defense Evasion".into(), platform: &["Windows", "Linux", "macOS"], detection: "Monitor for abnormal database query patterns" },
        ]);

        m.insert("CWE-94", vec![
            MitreTechnique { technique_id: "T1190".into(), name: "Exploit Public-Facing Application".into(), tactic: "Initial Access".into(), platform: &["Web"], detection: "RCE detection signatures" },
            MitreTechnique { technique_id: "T1203".into(), name: "Exploitation for Client Execution".into(), tactic: "Execution".into(), platform: &["Windows", "Linux", "macOS"], detection: "Monitor process execution chains" },
        ]);

        m.insert("CWE-601", vec![
            MitreTechnique { technique_id: "T1566".into(), name: "Phishing".into(), tactic: "Initial Access".into(), platform: &["Web"], detection: "URL scanning, redirect validation" },
            MitreTechnique { technique_id: "T1204".into(), name: "User Execution".into(), tactic: "Execution".into(), platform: &["Windows", "Linux", "macOS"], detection: "Monitor user interaction with untrusted links" },
        ]);

        m.insert("CWE-918", vec![
            MitreTechnique { technique_id: "T1596".into(), name: "Search Open Technical Databases".into(), tactic: "Reconnaissance".into(), platform: &["PRE"], detection: "Monitor for SSRF probes, outbound connection anomalies" },
            MitreTechnique { technique_id: "T1005".into(), name: "Data from Local System".into(), tactic: "Collection".into(), platform: &["IaaS"], detection: "Cloud API monitoring, metadata service access logging" },
        ]);

        // ===== Authentication & Identity =====
        m.insert("CWE-287", vec![
            MitreTechnique { technique_id: "T1110".into(), name: "Brute Force".into(), tactic: "Credential Access".into(), platform: &["Windows", "Linux", "macOS", "IaaS", "SaaS"], detection: "Failed login monitoring, account lockout events" },
            MitreTechnique { technique_id: "T1552".into(), name: "Unsecured Credentials".into(), tactic: "Credential Access".into(), platform: &["Windows", "Linux", "macOS"], detection: "Audit for credentials in files, env vars" },
            MitreTechnique { technique_id: "T1078".into(), name: "Valid Accounts".into(), tactic: "Defense Evasion".into(), platform: &["Windows", "Linux", "macOS", "IaaS", "SaaS"], detection: "Monitor unusual account usage" },
        ]);

        m.insert("CWE-798", vec![
            MitreTechnique { technique_id: "T1552".into(), name: "Unsecured Credentials".into(), tactic: "Credential Access".into(), platform: &["Windows", "Linux", "macOS", "SaaS"], detection: "Secrets scanning, code repository audits" },
            MitreTechnique { technique_id: "T1078".into(), name: "Valid Accounts".into(), tactic: "Defense Evasion".into(), platform: &["IaaS", "SaaS"], detection: "Credential usage anomalies" },
        ]);

        m.insert("CWE-522", vec![
            MitreTechnique { technique_id: "T1552".into(), name: "Unsecured Credentials".into(), tactic: "Credential Access".into(), platform: &["Windows", "Linux", "macOS"], detection: "Secrets scanning, credential exposure monitoring" },
            MitreTechnique { technique_id: "T1555".into(), name: "Credentials from Password Stores".into(), tactic: "Credential Access".into(), platform: &["Windows", "Linux", "macOS"], detection: "Monitor password store access" },
        ]);

        m.insert("CWE-613", vec![
            MitreTechnique { technique_id: "T1098".into(), name: "Account Manipulation".into(), tactic: "Persistence".into(), platform: &["Windows", "Azure AD", "SaaS"], detection: "Monitor session token manipulation" },
            MitreTechnique { technique_id: "T1528".into(), name: "Steal Application Access Token".into(), tactic: "Credential Access".into(), platform: &["SaaS"], detection: "OAuth token monitoring" },
        ]);

        // ===== TLS / Cryptography =====
        m.insert("CWE-327", vec![
            MitreTechnique { technique_id: "T1573".into(), name: "Encrypted Channel".into(), tactic: "Command and Control".into(), platform: &["Windows", "Linux", "macOS"], detection: "TLS fingerprint analysis, protocol version monitoring" },
            MitreTechnique { technique_id: "T1552".into(), name: "Unsecured Credentials".into(), tactic: "Credential Access".into(), platform: &["Network"], detection: "Monitor for weak cipher negotiation" },
        ]);

        m.insert("CWE-311", vec![
            MitreTechnique { technique_id: "T1040".into(), name: "Network Sniffing".into(), tactic: "Credential Access".into(), platform: &["Windows", "Linux", "macOS", "Network"], detection: "Network monitoring, encryption enforcement" },
        ]);

        m.insert("CWE-295", vec![
            MitreTechnique { technique_id: "T1557".into(), name: "Adversary-in-the-Middle".into(), tactic: "Credential Access".into(), platform: &["Windows", "Linux", "macOS", "Network"], detection: "Certificate validation monitoring, CA pinning" },
        ]);

        m.insert("CWE-326", vec![
            MitreTechnique { technique_id: "T1600".into(), name: "Weaken Encryption".into(), tactic: "Defense Evasion".into(), platform: &["Windows", "Linux", "macOS"], detection: "Monitor key sizes and algorithm strength" },
        ]);

        // ===== CORS, CSP, Headers =====
        m.insert("CWE-942", vec![
            MitreTechnique { technique_id: "T1190".into(), name: "Exploit Public-Facing Application".into(), tactic: "Initial Access".into(), platform: &["Web"], detection: "CORS header validation, origin checking" },
        ]);

        m.insert("CWE-1021", vec![
            MitreTechnique { technique_id: "T1189".into(), name: "Drive-by Compromise".into(), tactic: "Initial Access".into(), platform: &["Web"], detection: "X-Frame-Options and frame-ancestors CSP validation" },
        ]);

        m.insert("CWE-693", vec![
            MitreTechnique { technique_id: "T1562".into(), name: "Impair Defenses".into(), tactic: "Defense Evasion".into(), platform: &["Web"], detection: "CSP header validation, content type checking" },
        ]);

        // ===== OAuth / JWT / API =====
        m.insert("CWE-862", vec![
            MitreTechnique { technique_id: "T1554".into(), name: "Compromise Client Software Binary".into(), tactic: "Persistence".into(), platform: &["SaaS"], detection: "OAuth scope monitoring" },
            MitreTechnique { technique_id: "T1528".into(), name: "Steal Application Access Token".into(), tactic: "Credential Access".into(), platform: &["SaaS"], detection: "Token usage anomalies" },
        ]);

        m.insert("CWE-287_JWT", vec![
            MitreTechnique { technique_id: "T1552".into(), name: "Unsecured Credentials".into(), tactic: "Credential Access".into(), platform: &["SaaS", "Web"], detection: "JWT algorithm verification" },
        ]);

        m.insert("CWE-200", vec![
            MitreTechnique { technique_id: "T1592".into(), name: "Gather Victim Host Information".into(), tactic: "Reconnaissance".into(), platform: &["PRE"], detection: "Monitor for unusual information disclosure" },
        ]);

        // ===== Infrastructure & Network =====
        m.insert("CWE-521", vec![
            MitreTechnique { technique_id: "T1110".into(), name: "Brute Force".into(), tactic: "Credential Access".into(), platform: &["Windows", "Linux", "macOS", "Network"], detection: "Password policy enforcement" },
        ]);

        m.insert("CWE-22", vec![
            MitreTechnique { technique_id: "T1006".into(), name: "Direct Volume Access".into(), tactic: "Collection".into(), platform: &["Windows", "Linux", "macOS"], detection: "Path traversal detection, input validation" },
            MitreTechnique { technique_id: "T1083".into(), name: "File and Directory Discovery".into(), tactic: "Discovery".into(), platform: &["Windows", "Linux", "macOS"], detection: "Monitor filesystem access patterns" },
        ]);

        m.insert("CWE-306", vec![
            MitreTechnique { technique_id: "T1068".into(), name: "Exploitation for Privilege Escalation".into(), tactic: "Privilege Escalation".into(), platform: &["Windows", "Linux", "macOS"], detection: "Authentication bypass monitoring" },
        ]);

        m.insert("CWE-276", vec![
            MitreTechnique { technique_id: "T1548".into(), name: "Abuse Elevation Control Mechanism".into(), tactic: "Privilege Escalation".into(), platform: &["Windows", "Linux", "macOS"], detection: "Permission audit" },
        ]);

        // ===== Container & Cloud =====
        m.insert("CWE-269_CONTAINER", vec![
            MitreTechnique { technique_id: "T1611".into(), name: "Escape to Host".into(), tactic: "Privilege Escalation".into(), platform: &["Containers"], detection: "Container breakout monitoring" },
            MitreTechnique { technique_id: "T1609".into(), name: "Container Administration Command".into(), tactic: "Execution".into(), platform: &["Containers"], detection: "Kubernetes API audit logging" },
        ]);

        m.insert("CWE-269_K8S", vec![
            MitreTechnique { technique_id: "T1610".into(), name: "Deploy Container".into(), tactic: "Execution".into(), platform: &["Containers"], detection: "Container creation monitoring" },
            MitreTechnique { technique_id: "T1553".into(), name: "Subvert Trust Controls".into(), tactic: "Defense Evasion".into(), platform: &["Containers"], detection: "Kubernetes RBAC audit" },
        ]);

        m.insert("CWE-1104", vec![
            MitreTechnique { technique_id: "T1611".into(), name: "Escape to Host".into(), tactic: "Privilege Escalation".into(), platform: &["Containers"], detection: "Privileged container monitoring" },
        ]);

        // ===== IaC / Misconfiguration =====
        m.insert("CWE-16", vec![
            MitreTechnique { technique_id: "T1546".into(), name: "Event Triggered Execution".into(), tactic: "Persistence".into(), platform: &["IaaS"], detection: "Infrastructure configuration monitoring" },
        ]);

        m.insert("CWE-703", vec![
            MitreTechnique { technique_id: "T1190".into(), name: "Exploit Public-Facing Application".into(), tactic: "Initial Access".into(), platform: &["Web"], detection: "Error handling validation" },
        ]);

        m.insert("CWE-770", vec![
            MitreTechnique { technique_id: "T1499".into(), name: "Endpoint Denial of Service".into(), tactic: "Impact".into(), platform: &["Windows", "Linux", "macOS", "Network"], detection: "Resource limit monitoring" },
        ]);

        m.insert("CWE-1286", vec![
            MitreTechnique { technique_id: "T1190".into(), name: "Exploit Public-Facing Application".into(), tactic: "Initial Access".into(), platform: &["Web"], detection: "Input validation at OpenAPI/Swagger endpoints" },
        ]);

        // ===== Subdomain Takeover =====
        m.insert("CWE-644", vec![
            MitreTechnique { technique_id: "T1584".into(), name: "Compromise Infrastructure".into(), tactic: "Resource Development".into(), platform: &["PRE"], detection: "DNS CNAME monitoring" },
        ]);

        // ===== Port Scanning / Discovery =====
        m.insert("CWE-200_PORTSCAN", vec![
            MitreTechnique { technique_id: "T1046".into(), name: "Network Service Discovery".into(), tactic: "Discovery".into(), platform: &["Windows", "Linux", "macOS", "Network"], detection: "Port scan detection, network flow analysis" },
        ]);

        m.insert("CWE-200_DNS", vec![
            MitreTechnique { technique_id: "T1595".into(), name: "Active Scanning".into(), tactic: "Reconnaissance".into(), platform: &["PRE"], detection: "DNS query monitoring, zone transfer attempts" },
        ]);

        m.insert("CWE-200_TLS", vec![
            MitreTechnique { technique_id: "T1592".into(), name: "Gather Victim Host Information".into(), tactic: "Reconnaissance".into(), platform: &["PRE"], detection: "Certificate transparency log monitoring" },
        ]);

        // ===== Dependency & Supply Chain =====
        m.insert("CWE-937", vec![
            MitreTechnique { technique_id: "T1195".into(), name: "Supply Chain Compromise".into(), tactic: "Initial Access".into(), platform: &["Windows", "Linux", "macOS", "SaaS"], detection: "Software composition analysis" },
        ]);

        m.insert("CWE-1103", vec![
            MitreTechnique { technique_id: "T1195".into(), name: "Supply Chain Compromise".into(), tactic: "Initial Access".into(), platform: &["Web"], detection: "Dependency auditing, CVE monitoring" },
        ]);

        // ===== SAST / Secrets =====
        m.insert("CWE-312", vec![
            MitreTechnique { technique_id: "T1552".into(), name: "Unsecured Credentials".into(), tactic: "Credential Access".into(), platform: &["Windows", "Linux", "macOS"], detection: "Hardcoded secret scanning" },
        ]);

        m.insert("CWE-532", vec![
            MitreTechnique { technique_id: "T1552".into(), name: "Unsecured Credentials".into(), tactic: "Credential Access".into(), platform: &["Windows", "Linux", "macOS"], detection: "Log auditing for credential exposure" },
        ]);

        // ===== Schema / API Drift =====
        m.insert("CWE-API_DRIFT", vec![
            MitreTechnique { technique_id: "T1190".into(), name: "Exploit Public-Facing Application".into(), tactic: "Initial Access".into(), platform: &["Web"], detection: "API version monitoring, schema validation" },
        ]);

        m.insert("CWE-API_SHADOW", vec![
            MitreTechnique { technique_id: "T1592".into(), name: "Gather Victim Host Information".into(), tactic: "Reconnaissance".into(), platform: &["PRE"], detection: "API discovery monitoring" },
        ]);

        m
    };
}

/// Mapping from CWE numbers to finding type keywords for general classification.
const CWE_KEYWORDS: &[(&str, &[&str])] = &[
    ("CWE-79", &["xss", "cross-site", "cross_site"]),
    ("CWE-89", &["sqli", "sql injection"]),
    ("CWE-94", &["rce", "remote code", "command injection"]),
    ("CWE-601", &["redirect", "open redirect"]),
    ("CWE-918", &["ssrf"]),
    ("CWE-287", &["auth", "authentication", "jwt", "oauth"]),
    ("CWE-798", &["hardcoded", "secret", "password"]),
    ("CWE-942", &["cors"]),
    ("CWE-1021", &["clickjack", "x-frame"]),
    ("CWE-693", &["csp", "content security"]),
    ("CWE-327", &["weak cipher", "tls", "ssl", "rc4", "des"]),
    ("CWE-295", &["certificate", "cert validation"]),
    ("CWE-22", &["path traversal", "lfi"]),
    ("CWE-522", &["credential", "leak"]),
    ("CWE-306", &["missing auth"]),
    ("CWE-644", &["subdomain takeover", "cname"]),
    ("CWE-312", &["secret", "api key", "token"]),
    ("CWE-937", &["dependency", "cve", "vulnerability"]),
    ("CWE-276", &["permission", "rbac", "iam"]),
    ("CWE-16", &["misconfig", "misconfiguration"]),
    ("CWE-1104", &["privileged", "root", "container"]),
    ("CWE-770", &["dos", "resource limit", "rate limit"]),
    ("CWE-200", &["information disclosure", "info leak"]),
    ("CWE-862", &["authorization", "idor"]),
];

/// Main entry point: maps findings to MITRE ATT&CK techniques.
///
/// For each finding, this function looks up relevant MITRE techniques by:
/// 1. Direct CWE lookup in the compliance map
/// 2. Keyword matching against the finding's payload/description
pub async fn execute(
    templates: &[MitreMappingTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
    mut findings: Vec<FindingOwned>,
) -> Option<FindingOwned> {
    for template in templates {
        if !template.enable_mapping {
            continue;
        }

        let mut total_techniques = 0usize;
        let mut all_technique_ids: Vec<String> = Vec::new();
        let mut all_tactics: Vec<String> = Vec::new();

        for finding in &mut findings {
            let cwe = finding.metadata.get("cwe").cloned();
            let payload_lower = finding.matched_at.to_lowercase();

            // Step 1: Direct CWE lookup
            let mut matched = Vec::new();
            if let Some(ref cwe_val) = cwe {
                if let Some(techniques) = MITRE_MAP.get(cwe_val.as_str()) {
                    matched.extend(techniques.iter().cloned());
                }
            }

            // Step 2: Keyword-based matching if no CWE match
            if matched.is_empty() {
                for (cwe_key, keywords) in CWE_KEYWORDS {
                    if keywords.iter().any(|kw| payload_lower.contains(kw)) {
                        if let Some(techniques) = MITRE_MAP.get(*cwe_key) {
                            matched.extend(techniques.iter().cloned());
                        }
                        break;
                    }
                }
            }

            // Step 3: Deduplicate techniques by ID
            matched.sort_by(|a, b| a.technique_id.cmp(&b.technique_id));
            matched.dedup_by(|a, b| a.technique_id == b.technique_id);

            if !matched.is_empty() {
                let technique_ids: Vec<String> = matched.iter().map(|t| t.technique_id.clone()).collect();
                let tactic_list: Vec<&str> = matched.iter().map(|t| t.tactic.as_str()).collect();

                // Tag the finding with MITRE technique IDs and tactics
                finding.metadata.insert("mitre_techniques".to_string(), technique_ids.join(", "));
                finding.metadata.insert("mitre_tactics".to_string(), tactic_list.join(", "));

                // Store full technique details as JSON for reporting
                let details: Vec<String> = matched.iter().map(|t| {
                    format!("{}:{} ({})", t.technique_id, t.name, t.tactic)
                }).collect();
                finding.metadata.insert("mitre_details".to_string(), details.join(" | "));

                total_techniques += matched.len();
                all_technique_ids.extend(technique_ids);
                all_tactics.extend(tactic_list.into_iter().map(|s| s.to_string()));
            }
        }

        if total_techniques > 0 {
            all_technique_ids.sort();
            all_technique_ids.dedup();
            all_tactics.sort();
            all_tactics.dedup();

            let mut metadata = HashMap::new();
            metadata.insert("mitre_techniques".to_string(), all_technique_ids.join(", "));
            metadata.insert("mitre_tactics".to_string(), all_tactics.join(", "));
            metadata.insert("reporting".to_string(), "MITRE ATT&CK Mapping Complete".to_string());

            tracing::info!(
                findings = findings.len(),
                techniques = total_techniques,
                "MITRE ATT&CK mapping completed"
            );

            return Some(FindingOwned {
                template_id: template_id.to_string(),
                template_name: template_meta.template_name().to_string(),
                severity: template_meta.template_severity().to_string(),
                target: "System".to_string(),
                matched_at: format!(
                    "Mapped {} findings to {} unique MITRE ATT&CK techniques across {} tactics: {}",
                    findings.len(),
                    all_technique_ids.len(),
                    all_tactics.len(),
                    all_technique_ids.join(", ")
                ),
                description: None,
                solution: None,
                extracted_data: None,
                metadata,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(payload: &str, cwe: Option<&str>) -> FindingOwned {
        let mut metadata = HashMap::new();
        if let Some(c) = cwe {
            metadata.insert("cwe".to_string(), c.to_string());
        }
        FindingOwned {
            template_id: "test".to_string(),
            template_name: "Test".to_string(),
            severity: "High".to_string(),
            target: "test".to_string(),
            matched_at: payload.to_string(),
            description: None,
            solution: None,
            extracted_data: None,
            metadata,
        }
    }

    #[tokio::test]
    async fn test_xss_mapping() {
        let template = MitreMappingTemplate { enable_mapping: true };
        let findings = vec![make_finding("XSS vulnerability in search", Some("CWE-79"))];
        let info = TemplateInfo {
            name: "Test Template".to_string(),
            severity: "High".to_string(),
            description: Some("test".to_string()),
            ..Default::default()
        };

        let result = execute(&[template], "test", &info, findings).await;
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(r.matched_at.contains("T1190"));
        assert!(r.metadata.contains_key("mitre_techniques"));
    }

    #[tokio::test]
    async fn test_sqli_mapping() {
        let template = MitreMappingTemplate { enable_mapping: true };
        let findings = vec![make_finding("SQL injection in login", None)];
        let info = TemplateInfo { name: "Test".to_string(), severity: "High".to_string(), description: Some("test".to_string()), ..Default::default() };

        let result = execute(&[template], "test", &info, findings).await;
        assert!(result.is_some());
        let r = result.unwrap();
        // Should match via keyword "sql injection"
        assert!(r.metadata.get("mitre_techniques").map_or(false, |v| v.contains("T1190")));
    }

    #[tokio::test]
    async fn test_no_mapping_when_disabled() {
        let template = MitreMappingTemplate { enable_mapping: false };
        let findings = vec![make_finding("test", Some("CWE-79"))];
        let info = TemplateInfo { name: "Test".to_string(), severity: "High".to_string(), description: Some("test".to_string()), ..Default::default() };

        let result = execute(&[template], "test", &info, findings).await;
        assert!(result.is_none());
    }
}