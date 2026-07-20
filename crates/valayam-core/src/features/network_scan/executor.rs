use crate::core::result::ScanResult;
use crate::network::tcp;
use crate::network::udp;
use crate::template::schema::TemplateInfo;
use super::parser::NetworkRequestTemplate;
use chrono::Utc;
use regex::bytes::Regex;
use std::collections::HashMap;

/// Define commonly exposed services that should not be publicly accessible
const SENSITIVE_PORTS: &[u16] = &[
    22,   // SSH
    23,   // Telnet
    25,   // SMTP
    53,   // DNS
    135,  // MS RPC
    139,  // NetBIOS
    445,  // SMB
    1433, // MSSQL
    1434, // MSSQL Monitor
    1521, // Oracle
    3306, // MySQL
    3389, // RDP
    5432, // PostgreSQL
    5900, // VNC
    5901, // VNC
    6379, // Redis
    27017, // MongoDB
    11211, // Memcached
];

/// Extract service and version information from banner
fn identify_service_from_banner(port: u16, banner: &str) -> (String, Option<String>) {
    let banner_lower = banner.to_lowercase();

    // Determine service based on port and banner content
    let (service, version) = match port {
        22 => {
            // SSH banner usually looks like: "SSH-2.0-OpenSSH_7.4"
            if banner_lower.contains("ssh") {
                let version = extract_version_from_banner(banner);
                ("SSH".to_string(), version)
            } else {
                ("Unknown".to_string(), None)
            }
        }
        23 => {
            // Telnet banners vary widely
            if banner_lower.contains("telnet") {
                ("Telnet".to_string(), None)
            } else {
                ("Unknown".to_string(), None)
            }
        }
        25 => {
            // SMTP banners often contain server info
            if banner.contains("ESMTP") || banner.contains("Sendmail") ||
               banner.contains("Postfix") || banner.contains("Exim") ||
               banner.contains("Exchange") {
                let service_name = if banner.contains("Microsoft") || banner.contains("Exchange") {
                    "Microsoft SMTP"
                } else if banner.contains("Sendmail") {
                    "Sendmail"
                } else if banner.contains("Postfix") {
                    "Postfix"
                } else if banner.contains("Exim") {
                    "Exim"
                } else {
                    "SMTP Server"
                };
                (service_name.to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("smtp") || banner_lower.contains("mail") {
                ("SMTP".to_string(), extract_version_from_banner(banner))
            } else {
                ("SMTP".to_string(), None)
            }
        }
        53 => {
            // DNS doesn't usually give banners on TCP, but if it does...
            if banner_lower.contains("dns") || banner.contains("named") {
                ("DNS".to_string(), extract_version_from_banner(banner))
            } else {
                ("DNS".to_string(), None)
            }
        }
        135 => {
            if banner_lower.contains("msrpc") || banner.contains("Microsoft RPC") {
                ("MSRPC".to_string(), extract_version_from_banner(banner))
            } else {
                ("MSRPC".to_string(), None)
            }
        }
        139 | 445 => {
            if banner.contains("Samba") {
                ("SMB".to_string(), extract_version_from_banner(banner))
            } else if banner.contains("Microsoft") || banner.contains("Windows") {
                ("SMB".to_string(), extract_version_from_banner(banner))
            } else {
                ("SMB".to_string(), None)
            }
        }
        1433 => {
            if banner.contains("Microsoft") || banner.contains("SQL Server") {
                ("MSSQL".to_string(), extract_version_from_banner(banner))
            } else {
                ("MSSQL".to_string(), None)
            }
        }
        1434 => {
            if banner.contains("Microsoft") || banner.contains("SQL Server") {
                ("MSSQL Monitor".to_string(), extract_version_from_banner(banner))
            } else {
                ("MSSQL Monitor".to_string(), None)
            }
        }
        1521 => {
            if banner.contains("Oracle") {
                ("Oracle".to_string(), extract_version_from_banner(banner))
            } else {
                ("Oracle".to_string(), None)
            }
        }
        3306 => {
            if banner.contains("MySQL") {
                ("MySQL".to_string(), extract_version_from_banner(banner))
            } else if banner.contains("MariaDB") {
                ("MariaDB".to_string(), extract_version_from_banner(banner))
            } else {
                ("MySQL".to_string(), None)
            }
        }
        3389 => {
            if banner.contains("Remote Desktop") || banner.contains("Terminal Services") {
                ("RDP".to_string(), None) // RDP doesn't usually give version in banner
            } else {
                ("RDP".to_string(), None)
            }
        }
        5432 => {
            if banner.contains("PostgreSQL") {
                ("PostgreSQL".to_string(), extract_version_from_banner(banner))
            } else {
                ("PostgreSQL".to_string(), None)
            }
        }
        5900 | 5901 => {
            if banner.contains("RFB") { // VNC protocol identifier
                ("VNC".to_string(), extract_version_from_banner(banner))
            } else {
                ("VNC".to_string(), None)
            }
        }
        6379 => {
            if banner.contains("Redis") {
                let version = extract_version_from_banner(banner);
                // Redis often sends just "Redis" followed by version on newline
                if version.is_none() {
                    if banner.lines().count() > 1 {
                        // Try to get version from second line
                        let lines: Vec<&str> = banner.lines().collect();
                        if lines.len() > 1 {
                            return ( "Redis".to_string(), extract_version_from_banner(lines[1]) );
                        }
                    }
                }
                ("Redis".to_string(), version)
            } else {
                ("Redis".to_string(), None)
            }
        }
        27017 => {
            if banner.contains("MongoDB") {
                ("MongoDB".to_string(), extract_version_from_banner(banner))
            } else {
                ("MongoDB".to_string(), None)
            }
        }
        11211 => {
            if banner.contains("memcached") {
                ("Memcached".to_string(), extract_version_from_banner(banner))
            } else {
                ("Memcached".to_string(), None)
            }
        }
        _ => {
            // Generic detection based on banner content
            if banner_lower.contains("ssh") {
                ("SSH".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("http") || banner.contains("HTTP") {
                ("HTTP".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("ftp") {
                ("FTP".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("smtp") || banner_lower.contains("mail") {
                ("SMTP".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("dns") {
                ("DNS".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("mysql") {
                ("MySQL".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("postgres") {
                ("PostgreSQL".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("mongodb") {
                ("MongoDB".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("redis") {
                ("Redis".to_string(), extract_version_from_banner(banner))
            } else {
                ("Unknown".to_string(), None)
            }
        }
    };

    (service, version)
}

/// Extract version string from banner using common patterns
fn extract_version_from_banner(banner: &str) -> Option<String> {
    if banner.is_empty() {
        return None;
    }

    // Common version patterns
    let patterns = [
        r"[\d]+\.[\d]+\.[\d]+",           // X.Y.Z
        r"[\d]+\.[\d]+",                  // X.Y
        r"version[\s_-]*[\d]+\.[\d]+",    // version X.Y
        r"v[\d]+\.[\d]+",                 // vX.Y
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(mat) = re.find(banner) {
                return Some(mat.as_str().to_string());
            }
        }
    }

    None
}

/// Check if service version appears to be potentially vulnerable
fn check_vulnerability(service: &str, version: &Option<String>) -> Option<String> {
    let Some(ref version_str) = *version else {
        return None;
    };

    // Define version patterns that might indicate vulnerable versions
    let vuln_patterns: Vec<(&str, Vec<&str>)> = vec![
        ("SSH", vec!["OpenSSH_5", "OpenSSH_6", "OpenSSH_7.0", "OpenSSH_7.1", "OpenSSH_7.2"]),
        ("HTTP", vec!["Apache/2.2", "Apache/2.0", "nginx/1.0", "nginx/1.1", "nginx/1.2", "nginx/1.3", "nginx/1.4", "nginx/1.5", "nginx/1.6"]),
        ("MySQL", vec!["5.0", "5.1", "5.5"]),
        ("MariaDB", vec!["5.0", "5.1", "5.5"]),
        ("PostgreSQL", vec!["9.0", "9.1", "9.2", "9.3", "9.4"]),
        ("MongoDB", vec!["1.", "2.0", "2.2", "2.4", "2.6"]),
        ("Redis", vec!["1.", "2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.8"]),
        ("RDP", vec![]), // RDP version checking is complex, skip for now
        ("SMB", vec![]), // SMB version checking via banner is limited
    ];

    for &(service_name, ref patterns) in &vuln_patterns {
        if service.eq_ignore_ascii_case(service_name) {
            for pattern in patterns {
                if version_str.contains(pattern) {
                    return Some(format!("Potentially vulnerable {} version detected", service));
                }
            }
        }
    }

    None
}

/// Get remediation suggestion for a service
fn get_service_solution(service: &str, port: u16) -> Option<String> {
    let solution = match service {
        "SSH" => Some("Restrict SSH access to specific IP ranges using firewalls; use key-based authentication; disable password authentication; change default port if possible".to_string()),
        "Telnet" => Some("Disable Telnet immediately; use SSH instead for secure remote access".to_string()),
        "SMTP" => Some("Configure SMTP to require authentication for relay; implement SPF, DKIM, DMARC; restrict access to mail servers".to_string()),
        "DNS" => Some("Restrict DNS zone transfers to authorized servers; implement response rate limiting; use DNSSEC".to_string()),
        "MSRPC" => Some("Block MSRPC ports at firewall; keep Windows systems patched".to_string()),
        "NetBIOS" => Some("Disable NetBIOS over TCP/IP; block ports 137-139 at firewall".to_string()),
        "SMB" => Some("Disable SMBv1; patch regularly; restrict access to file shares; use SMB signing".to_string()),
        "MSSQL" => Some("Use strong sa password; apply principle of least privilege; enable network encryption; patch regularly".to_string()),
        "Oracle" => Some("Change default passwords; apply CPU patches regularly; use database firewalls".to_string()),
        "MySQL" | "MariaDB" => Some("Use strong root password; bind to localhost if possible; remove anonymous users; update regularly".to_string()),
        "PostgreSQL" => Some("Use strong passwords; modify pg_hba.conf to restrict connections; enable SSL; keep updated".to_string()),
        "RDP" => Some("Enable Network Level Authentication; use strong passwords; limit users who can RDP; consider VPN gateway".to_string()),
        "VNC" => Some("Use strong passwords; tunnel VNC over SSH; consider disabling if not needed".to_string()),
        "Redis" => Some("Require authentication; bind to localhost or internal network only; rename dangerous commands; use firewall rules".to_string()),
        "MongoDB" => Some("Enable authentication; bind to localhost; disable unnecessary interfaces; keep updated".to_string()),
        "Memcached" => Some("Bind to localhost or use firewall; enable SASL authentication if available".to_string()),
        "HTTP" => Some("Keep web server software updated; disable unnecessary modules; use WAF; implement HTTPS".to_string()),
        "FTP" => Some("Use SFTP or FTPS instead of plain FTP; implement strong authentication".to_string()),
        _ => None
    };

    // Add port-specific advice for high-risk exposures
    let solution = if matches!(port, 22 | 23 | 3389 | 5900 | 5901) {
        Some(format!("{} Exposure Risk: This service provides remote administrative access and should never be exposed directly to the internet. Use VPN or jump host for remote management.", service))
    } else if matches!(port, 1433 | 1434 | 3306 | 5432 | 1521 | 27017 | 6379) {
        Some(format!("{} Exposure Risk: Database exposed to network - implement network segmentation, strong authentication, and encryption", service))
    } else {
        solution
    };

    solution
}

/// Get CVSS score estimate based on service exposure risk
fn get_cvss_score(service: &str, _port: u16) -> Option<f32> {
    // Base score adjusted by service criticality and exposure risk
    let base_score = match service {
        "SSH" | "RDP" | "VNC" => 9.0, // Remote admin - critical if exposed
        "Telnet" => 9.5, // Especially dangerous due to no encryption
        "MSSQL" | "MySQL" | "MariaDB" | "PostgreSQL" | "Oracle" | "MongoDB" => 8.5, // Databases
        "Redis" | "Memcached" => 8.0, // Memory caches - often contain sensitive data
        "SMB" => 7.5, // File sharing - risk of data exposure and lateral movement
        "DNS" => 6.0, // Can be used for amplification and tunneling
        "SMTP" => 5.0, // Misconfiguration can lead to spam relay
        "HTTP" | "FTP" => 4.0, // Web services - depends on configuration
        _ => 3.0, // Low risk services
    };

    Some(base_score)
}

pub async fn execute(
    _target_url: &str,
    target_host: &str,
    network_rules: &[NetworkRequestTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for net_rule in network_rules {
        let host_to_scan = net_rule.host.replace("{{Hostname}}", target_host);

        tracing::debug!(target = %host_to_scan, ports = ?net_rule.ports, protocol = %net_rule.protocol, "Starting network port scan");

        // Process ports - convert both UDP and TCP results to a common format
        let mut findings = Vec::new();
        let mut critical_findings = Vec::new();

        // Local type to unify UDP and TCP port results
        struct ScanPortResult {
            port: u16,
            banner_text: String,
        }

        let is_udp = net_rule.protocol.to_lowercase() == "udp";
        let port_results: Vec<ScanPortResult> = if is_udp {
            let results = udp::scan_ports(
                &host_to_scan,
                &net_rule.ports,
                net_rule.banner_timeout_ms,
                false,
            )
            .await;
            results.into_iter().map(|r| ScanPortResult {
                port: r.port,
                banner_text: r.response.as_ref()
                    .map(|v| String::from_utf8_lossy(v).to_string())
                    .unwrap_or_default(),
            }).collect()
        } else {
            let results = tcp::scan_ports(
                &host_to_scan,
                &net_rule.ports,
                net_rule.banner_timeout_ms,
                false,
            )
            .await;
            results.into_iter().map(|r| ScanPortResult {
                port: r.port,
                banner_text: r.banner.unwrap_or_default(),
            }).collect()
        };

        if port_results.is_empty() {
            continue;
        }

        for port_result in &port_results {
            let (service, version) = identify_service_from_banner(port_result.port,
                                                                &port_result.banner_text);

            // Check for potential vulnerabilities
            let vuln_check = check_vulnerability(&service, &version);

            // Get remediation advice
            let solution = get_service_solution(&service, port_result.port);

            // Get CVSS score estimate
            let cvss_score = get_cvss_score(&service, port_result.port);

            // Build service description
            let service_desc = match &version {
                Some(v) => format!("{} {}", service, v),
                None => service.clone(),
            };

            // Check if this is a particularly sensitive service
            let is_critical = SENSITIVE_PORTS.contains(&port_result.port);

            // Create base finding message
            let base_finding = format!("Port {} open - {}", port_result.port, service_desc);

            // Build enhanced finding with context
            let mut finding_details = String::new();
            finding_details.push_str(&base_finding);

            if let Some(vuln) = &vuln_check {
                finding_details.push_str(format!(" -> {}", vuln).as_str());
            }

            // Prepare enhanced result data (store additional info in compliance map)
            let mut compliance = HashMap::new();
            compliance.insert("service".to_string(), service.clone());
            if let Some(v) = &version {
                compliance.insert("version".to_string(), v.clone());
            }
            if let Some(vuln) = &vuln_check {
                compliance.insert("vulnerability".to_string(), vuln.clone());
            }
            if let Some(sol) = &solution {
                compliance.insert("solution".to_string(), sol.clone());
            }
            if let Some(score) = &cvss_score {
                compliance.insert("cvss_score".to_string(), score.to_string());
            }

            if net_rule.matchers.is_empty() {
                // No matchers: any open port is a finding
                let result = ScanResult {
                    timestamp: Utc::now(),
                    template_id: template_id.to_string(),
                    template_name: template_info.name.clone(),
                    template_severity: {
                        // Determine severity based on service criticality and findings
                        let severity = template_info.severity.clone();
                        if is_critical && !vuln_check.is_none() {
                            // Critical service with vulnerability - elevate severity
                            if severity == "Info" { "Medium".to_string() }
                            else if severity == "Low" { "High".to_string() }
                            else if severity == "Medium" { "High".to_string() }
                            else { severity }
                        } else if is_critical {
                            // Critical service but no vuln found - still elevated
                            if severity == "Info" { "Low".to_string() }
                            else if severity == "Low" { "Medium".to_string() }
                            else { severity }
                        } else {
                            severity
                        }
                    },
                    target: format!("{}:{}", host_to_scan, port_result.port),
                    payload: finding_details,
                    cvss_score: None,
                    reference: None,
                    solution: None,
                    tags: Vec::new(),
                    compliance,
                };

                if is_critical {
                    critical_findings.push(result);
                } else {
                    findings.push(result);
                }
            } else {
                // With matchers: evaluate against banners
                let banner_text = &port_result.banner_text;

                'matcher_loop: for matcher in &net_rule.matchers {
                    if matcher.r#type == "regex" && matcher.part == "banner" {
                        for pattern in &matcher.regex {
                            let Ok(re) = Regex::new(pattern) else {
                                continue;
                            };
                            if re.is_match(banner_text.as_bytes()) {
                                tracing::debug!(port = %port_result.port, pattern = %pattern, "Vulnerability banner match found");

                                let mut payload = format!(
                                    "Port {} matched '{}' — {}",
                                    port_result.port,
                                    pattern,
                                    banner_text.trim()
                                );

                                // Add service context to payload
                                if service != "Unknown" {
                                    payload.push_str(format!(", Service: {} {}", service, version.as_deref().unwrap_or("")).as_str());
                                }

                                let mut compliance = HashMap::new();
                                compliance.insert("service".to_string(), service.clone());
                                if let Some(v) = &version {
                                    compliance.insert("version".to_string(), v.clone());
                                }
                                compliance.insert("matched_pattern".to_string(), pattern.to_string());
                                if let Some(vuln) = &vuln_check {
                                    compliance.insert("vulnerability".to_string(), vuln.clone());
                                }

                                let result = ScanResult {
                                    timestamp: Utc::now(),
                                    template_id: template_id.to_string(),
                                    template_name: template_info.name.clone(),
                                    template_severity: {
                                        // Determine severity based on service criticality and findings
                                        let severity = template_info.severity.clone();
                                        if is_critical && !vuln_check.is_none() {
                                            // Critical service with vulnerability - elevate severity
                                            if severity == "Info" { "Medium".to_string() }
                                            else if severity == "Low" { "High".to_string() }
                                            else if severity == "Medium" { "High".to_string() }
                                            else { severity }
                                        } else if is_critical {
                                            // Critical service but no vuln found - still elevated
                                            if severity == "Info" { "Low".to_string() }
                                            else if severity == "Low" { "Medium".to_string() }
                                            else { severity }
                                        } else {
                                            severity
                                        }
                                    },
                                    target: format!("{}:{}", host_to_scan, port_result.port),
                                    payload,
                                    cvss_score: None,
                                    reference: None,
                                    solution: None,
                                    tags: Vec::new(),
                                    compliance,
                                };

                                if is_critical {
                                    critical_findings.push(result);
                                } else {
                                    findings.push(result);
                                }

                                // Break out of matcher loops since we found a match
                                break 'matcher_loop;
                            }
                        }
                    }
                }
            }
        }

        // Return critical findings first, then others
        let mut all_findings = Vec::new();
        all_findings.extend(critical_findings);
        all_findings.extend(findings);

        if !all_findings.is_empty() {
            return Some(all_findings.remove(0));
        }
    }

    None
}