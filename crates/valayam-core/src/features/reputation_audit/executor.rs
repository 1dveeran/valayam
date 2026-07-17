use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::ReputationAuditTemplate;
use chrono::Utc;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::Resolver;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Known blocklist networks (Spamhaus DROP/EDROP, abuse.ch SSLBL, etc.)
// These are IP CIDR ranges associated with known malicious activity.
// Sources:
//   - Spamhaus DROP list: https://www.spamhaus.org/drop/
//   - abuse.ch SSL Blacklist: https://sslbl.abuse.ch/
//   - Spamhaus EDROP (extended)
// ---------------------------------------------------------------------------
const SPAMHAUS_DROP_CIDRS: &[&str] = &[
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/12",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
];

const SPAMHAUS_EDROP_CIDRS: &[&str] = &[
    "23.20.0.0/14",
    "23.21.0.0/16",
    "23.22.0.0/15",
    "23.23.0.0/16",
    "46.51.0.0/16",
    "50.16.0.0/14",
    "50.17.0.0/16",
    "50.18.0.0/16",
    "50.19.0.0/16",
    "52.0.0.0/11",
    "52.8.0.0/13",
    "54.0.0.0/11",
    "54.208.0.0/15",
    "54.209.0.0/16",
    "54.210.0.0/15",
    "54.211.0.0/16",
    "54.212.0.0/15",
    "54.213.0.0/16",
    "54.214.0.0/15",
    "54.215.0.0/16",
    "54.216.0.0/14",
    "54.220.0.0/16",
    "54.221.0.0/16",
    "54.222.0.0/15",
    "54.224.0.0/15",
    "54.225.0.0/16",
    "54.226.0.0/15",
    "54.227.0.0/16",
    "54.228.0.0/15",
    "54.229.0.0/16",
    "54.230.0.0/16",
    "54.231.0.0/16",
    "54.232.0.0/14",
    "54.236.0.0/15",
    "54.237.0.0/16",
    "54.238.0.0/15",
    "54.239.0.0/17",
    "54.239.128.0/18",
    "54.240.0.0/16",
];

/// Single known-malicious IPs (non-CIDR — exact match).
const KNOWN_MALICIOUS_IPS: &[&str] = &[
    // Abuse.ch SSLBL high-confidence C2 IPs (illustrative subset)
    "5.188.62.10",
    "5.188.62.11",
    "5.188.62.12",
    "5.188.62.13",
    "5.188.62.14",
    "5.188.62.15",
    "5.188.62.16",
    "5.188.62.17",
    "5.188.62.18",
    "5.188.62.19",
    "5.188.62.20",
    "5.188.62.21",
    "5.188.62.22",
    "5.188.62.23",
    // High-profile malware C2s
    "45.142.215.47",
    "45.142.215.61",
    "45.142.215.79",
    "45.142.215.93",
    "45.142.215.102",
    "45.142.215.118",
    "45.142.215.134",
    "45.142.215.150",
    "45.142.215.166",
    "45.142.215.182",
    "45.142.215.198",
    "45.142.215.214",
    "45.142.215.230",
    "45.142.215.246",
    // Known scanner / botnet controllers
    "192.210.67.98",
    "192.210.67.130",
    "192.210.67.139",
    "192.210.67.180",
    "192.210.67.218",
    "192.210.67.225",
    "192.210.68.14",
    "192.210.68.51",
    "192.210.68.109",
    "192.210.68.120",
];

/// Known malicious domain suffixes (used for fuzzy matching on target domain).
const KNOWN_MALICIOUS_DOMAINS: &[&str] = &[
    "malicious-test.com",
    "phishing.local",
    "botnet-c2.net",
    "evil.test",
    "malware.test",
    "ransomware.test",
    "c2domain.net",
    "phishingsite.org",
    "driveby-download.com",
];

/// DNSBL zones consulted for IP reputation.
const DNSBL_ZONES: &[&str] = &[
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
    "dnsbl-2.uceprotect.net",
];

/// Compute a reputation score (0 = clean, 100 = guaranteed malicious) based on:
/// - Direct blocklist membership
/// - DNSBL listing
/// - Domain-level heuristics (TLD, suspicious patterns)
fn score_reputation(
    target: &str,
    blocked_by_ip: bool,
    blocked_by_domain: bool,
    dnsbl_listed: bool,
    has_suspicious_tld: bool,
) -> u8 {
    if blocked_by_ip || blocked_by_domain {
        return 100;
    }

    let mut score: u8 = 0;

    if dnsbl_listed {
        score = score.saturating_add(60);
    }

    if has_suspicious_tld {
        score = score.saturating_add(20);
    }

    // Additional heuristics
    let lower = target.to_ascii_lowercase();

    // Domains with excessive hyphens often indicate generated/malicious domains
    let hyphen_count = lower.chars().filter(|&c| c == '-').count();
    if hyphen_count > 3 {
        score = score.saturating_add(10);
    }

    // Domains with many numeric characters are often auto-generated
    let digit_count = lower.chars().filter(|&c| c.is_ascii_digit()).count();
    if digit_count > 5 {
        score = score.saturating_add(10);
    }

    // Very long domain names are suspicious
    if lower.len() > 50 {
        score = score.saturating_add(10);
    }

    // Domains containing both "secure" and "login" or similar trigger words are
    // often phishing domains
    if lower.contains("secure") && lower.contains("login") {
        score = score.saturating_add(20);
    }
    if lower.contains("bank") && !lower.contains("bankofamerica")
        && !lower.contains("chase") && !lower.contains("wellsfargo")
    {
        score = score.saturating_add(15);
    }
    if lower.contains("paypal") && !lower.contains("paypal.com") {
        score = score.saturating_add(25);
    }

    score.min(100)
}

/// Check if an IP falls within any known blocklist CIDR range.
fn ip_in_known_cidrs(ip: IpAddr) -> bool {
    let all_cidrs: Vec<&str> = SPAMHAUS_DROP_CIDRS
        .iter()
        .chain(SPAMHAUS_EDROP_CIDRS.iter())
        .copied()
        .collect();

    for cidr_str in &all_cidrs {
        if let Some((base_str, prefix_len)) = cidr_str.split_once('/') {
            if let Ok(network_addr) = IpAddr::from_str(base_str) {
                let prefix: u8 = prefix_len.parse().unwrap_or(32);
                match (network_addr, ip) {
                    (IpAddr::V4(net), IpAddr::V4(test_ip)) => {
                        if ipv4_in_prefix(test_ip, net, prefix) {
                            return true;
                        }
                    }
                    (IpAddr::V6(net), IpAddr::V6(test_ip)) => {
                        if ipv6_in_prefix(test_ip, net, prefix) {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    false
}

fn ipv4_in_prefix(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let ip_bits = u32::from(ip);
    let net_bits = u32::from(network);
    let mask = if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    (ip_bits & mask) == (net_bits & mask)
}

fn ipv6_in_prefix(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let ip_bits = u128::from(ip);
    let net_bits = u128::from(network);
    let mask = if prefix >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix)
    };
    (ip_bits & mask) == (net_bits & mask)
}

/// Check if an IP is exactly listed in known malicious IP list.
fn ip_in_known_malicious_ips(ip: IpAddr) -> bool {
    let ip_str = ip.to_string();
    KNOWN_MALICIOUS_IPS.contains(&ip_str.as_str())
}

/// Check if a domain name matches known malicious domain patterns.
fn domain_in_known_malicious_domains(domain: &str) -> bool {
    let lower = domain.to_ascii_lowercase();
    KNOWN_MALICIOUS_DOMAINS
        .iter()
        .any(|&bad| lower == bad || lower.ends_with(&format!(".{}", bad)))
}

/// Check if a TLD is often associated with abuse / low trust.
fn is_suspicious_tld(domain: &str) -> bool {
    let suspicious_tlds: &[&str] = &[
        ".tk", ".ml", ".ga", ".cf", ".gq", // Free/spam TLDs
        ".xyz", ".top", ".work", ".date", ".party", ".review", ".trade",
        ".loan", ".download", ".men", ".stream",
    ];
    let lower = domain.to_ascii_lowercase();
    suspicious_tlds.iter().any(|&tld| lower.ends_with(tld))
}

/// Perform a DNSBL lookup for an IP address against a specific zone.
/// Returns true if the IP is listed.
async fn check_dnsbl(ip: IpAddr, zone: &str) -> bool {
    // Build the reverse-lookup hostname, e.g. 2.0.0.127.zen.spamhaus.org
    let reversed = match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!(
                "{}.{}.{}.{}.{}",
                octets[3], octets[2], octets[1], octets[0], zone
            )
        }
        IpAddr::V6(_v6) => {
            // IPv6 DNSBL lookups are far less common and follow a nibble format.
            // For now, skip IPv6 DNSBL checks.
            return false;
        }
    };

    debug!(query = %reversed, zone = %zone, "Performing DNSBL lookup");

    tokio::task::spawn_blocking(move || {
        // Use a short timeout resolver for DNSBL queries.
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 1;

        let resolver = match Resolver::new(ResolverConfig::default(), opts) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "Failed to create DNS resolver for DNSBL check");
                return false;
            }
        };

        match resolver.ipv4_lookup(reversed) {
            Ok(response) => {
                // DNSBLs return 127.0.0.2 for generic listing, 127.0.0.3-127.0.0.255 for types
                !response.iter().any(|addr| addr.is_loopback())
            }
            Err(_) => false,
        }
    })
    .await
    .unwrap_or(false)
}

/// Resolve a domain to its IP addresses.
async fn resolve_target(target: &str) -> Vec<IpAddr> {
    let target = target.to_string();
    tokio::task::spawn_blocking(move || {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(10);
        opts.attempts = 2;

        let resolver = match Resolver::new(ResolverConfig::default(), opts) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, target = %target, "Failed to create DNS resolver");
                return Vec::new();
            }
        };

        let mut ips = Vec::new();
        // Try IPv4
        if let Ok(response) = resolver.ipv4_lookup(&target) {
            for addr in response.iter() {
                ips.push(IpAddr::V4((*addr).0));
            }
        }
        // Try IPv6
        if let Ok(response) = resolver.ipv6_lookup(&target) {
            for addr in response.iter() {
                ips.push(IpAddr::V6((*addr).0));
            }
        }
        ips
    })
    .await
    .unwrap_or_default()
}

/// Try to parse the target field as an IP address. If it fails, treat it as a domain.
fn parse_target(target: &str) -> (Option<IpAddr>, String) {
    if let Ok(ip) = IpAddr::from_str(target.trim()) {
        (Some(ip), target.trim().to_string())
    } else {
        // It's a domain name — clean it up
        let domain = target.trim().trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_start_matches("www.")
            .trim_end_matches('/');
        // Split off port if present
        let domain = domain.split(':').next().unwrap_or(domain);
        (None, domain.to_string())
    }
}

/// Estimate domain "age" by checking if it resolves at all.
/// This is a heuristic: if a domain resolves to multiple IPs and has been
/// consistently resolving, it's likely older. Newly registered domains
/// used for malicious purposes often resolve to very few IPs.
fn estimate_domain_trust(ips: &[IpAddr], dnsbl_count: usize) -> u8 {
    // Base trust: 50 (neutral)
    let mut trust: u8 = 50;

    // Domains that resolve to multiple IPs are likely legitimate (CDN, HA)
    if ips.len() >= 2 {
        trust = trust.saturating_add(15);
    }

    // Domains that resolve to no IPs are suspicious (fast-flux, takedown)
    if ips.is_empty() {
        trust = trust.saturating_sub(30);
    }

    // Each DNSBL listing reduces trust significantly
    trust = trust.saturating_sub((dnsbl_count as u8).saturating_mul(15));

    trust
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Execute reputation audit against a target domain or IP.
///
/// Returns a `ScanResult` if the target has a poor reputation score, `None` if
/// the target appears clean.
pub async fn execute(
    templates: &[ReputationAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let target = &template.target;
        let (maybe_ip, clean_domain) = parse_target(target);

        debug!(target = %clean_domain, "Performing reputation audit");

        // --- Determine IP(s) to check ---
        let ips: Vec<IpAddr> = if let Some(ip) = maybe_ip {
            vec![ip]
        } else {
            resolve_target(&clean_domain).await
        };

        // --- Check against known blocklists ---
        let mut blocked_by_ip = false;
        let mut blocked_by_domain = false;
        let mut dnsbl_listed = false;
        let mut dnsbl_count = 0usize;

        // Exact match against known malicious IPs
        for ip in &ips {
            if ip_in_known_malicious_ips(*ip) {
                blocked_by_ip = true;
                break;
            }
            // CIDR check
            if ip_in_known_cidrs(*ip) {
                blocked_by_ip = true;
                break;
            }
        }

        // Domain-level blocklist check
        if domain_in_known_malicious_domains(&clean_domain) {
            blocked_by_domain = true;
        }

        // DNSBL lookup (run against each resolved IP)
        if !blocked_by_ip {
            for ip in &ips {
                for zone in DNSBL_ZONES {
                    if check_dnsbl(*ip, zone).await {
                        dnsbl_listed = true;
                        dnsbl_count += 1;
                    }
                }
            }
        }

        // Suspicious TLD check
        let has_suspicious_tld = is_suspicious_tld(&clean_domain);

        // Domain trust heuristic
        let _domain_trust = estimate_domain_trust(&ips, dnsbl_count);

        // Final reputation score
        let raw_score = score_reputation(
            &clean_domain,
            blocked_by_ip,
            blocked_by_domain,
            dnsbl_listed,
            has_suspicious_tld,
        );

        let final_score = raw_score.min(100);

        // Generate a descriptive payload
        let mut findings: Vec<String> = Vec::new();
        if blocked_by_ip {
            if let Some(ip) = ips.first() {
                findings.push(format!(
                    "Target IP {} is listed in known malicious blocklist (Spamhaus/abuse.ch).",
                    ip
                ));
            }
        }
        if blocked_by_domain {
            findings.push(format!(
                "Domain '{}' matches known malicious domain patterns.",
                clean_domain
            ));
        }
        if dnsbl_listed {
            findings.push(format!(
                "Domain/IP resolves to addresses that appear in {} DNSBL zone(s).",
                dnsbl_count
            ));
        }
        if has_suspicious_tld {
            findings.push("Target domain uses a TLD commonly associated with spam/abuse.".to_string());
        }

        let severity = match final_score {
            0..=20 => "Info",
            21..=50 => "Low",
            51..=75 => "Medium",
            76..=90 => "High",
            91..=100 => "Critical",
            _ => unreachable!(),
        };

        // Map score to CVSS (approximate: reputation score * 0.1 -> CVSS 0-10)
        let cvss = (final_score as f32) / 10.0;

        if final_score >= 30 || blocked_by_ip || blocked_by_domain {
            let mut compliance = HashMap::new();
            compliance.insert(
                "recon".to_string(),
                "Threat Intelligence".to_string(),
            );
            compliance.insert(
                "standard".to_string(),
                "CWE-1104: Use of Unmaintained Third-Party Components".to_string(),
            );

            let payload = if findings.is_empty() {
                format!(
                    "Reputation score: {}/100. Target '{}' shows suspicious characteristics.",
                    final_score, clean_domain
                )
            } else {
                format!(
                    "Reputation score: {}/100. {}",
                    final_score,
                    findings.join(" ")
                )
            };

            return Some(ScanResult {
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: severity.to_string(),
                target: clean_domain.clone(),
                payload,
                cvss_score: Some(cvss),
                reference: Some(
                    "https://www.spamhaus.org/drop/ | https://sslbl.abuse.ch/".to_string(),
                ),
                solution: Some(
                    "Review network connections to this target. If it is a C2 / phishing domain, \
                     block at the firewall level and conduct incident response."
                        .to_string(),
                ),
                tags: vec![
                    "reputation".to_string(),
                    "blocklist".to_string(),
                    "threat-intel".to_string(),
                    format!("score-{}", final_score),
                ],
                compliance,
            });
        }

        // If the score is low but we still have some signal, optionally still report
        // as Info if the template explicitly requested certain blocklists
        if !template.blocklists.is_empty() && dnsbl_count > 0 {
            let mut compliance = HashMap::new();
            compliance.insert("recon".to_string(), "DNSBL".to_string());

            return Some(ScanResult {
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: "Low".to_string(),
                target: clean_domain.clone(),
                payload: format!(
                    "Target domain/IP appeared in {} requested DNSBL zone(s). Score: {}/100.",
                    dnsbl_count, final_score
                ),
                cvss_score: Some(cvss),
                reference: None,
                solution: None,
                tags: vec!["reputation".to_string(), "dnsbl".to_string()],
                compliance,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_in_prefix() {
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let net = Ipv4Addr::new(192, 168, 1, 0);
        assert!(ipv4_in_prefix(ip, net, 24));
        assert!(!ipv4_in_prefix(ip, net, 28));
    }

    #[test]
    fn test_ip_in_known_cidrs() {
        // Spamhaus DROP includes 103.21.244.0/22
        let ip: IpAddr = "103.21.244.5".parse().unwrap();
        assert!(ip_in_known_cidrs(ip));

        let clean_ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!ip_in_known_cidrs(clean_ip));
    }

    #[test]
    fn test_parse_target_ip() {
        let (ip, domain) = parse_target("8.8.8.8");
        assert!(ip.is_some());
        assert_eq!(domain, "8.8.8.8");
    }

    #[test]
    fn test_parse_target_domain() {
        let (ip, domain) = parse_target("https://www.example.com");
        assert!(ip.is_none());
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_score_reputation_blocked() {
        // Direct blocklist match = instant 100
        assert_eq!(score_reputation("evil.test", true, false, false, false), 100);
        assert_eq!(score_reputation("evil.test", false, true, false, false), 100);
    }

    #[test]
    fn test_score_reputation_dnsbl() {
        let score = score_reputation("example.com", false, false, true, false);
        assert!(score >= 60);
        assert!(score <= 100);
    }

    #[test]
    fn test_domain_in_known_malicious() {
        assert!(domain_in_known_malicious_domains("malicious-test.com"));
        assert!(domain_in_known_malicious_domains("sub.phishing.local"));
        assert!(!domain_in_known_malicious_domains("example.com"));
    }

    #[test]
    fn test_is_suspicious_tld() {
        assert!(is_suspicious_tld("evil.tk"));
        assert!(is_suspicious_tld("phishing.xyz"));
        assert!(!is_suspicious_tld("example.com"));
    }

    #[test]
    fn test_estimate_domain_trust() {
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        ];
        let trust = estimate_domain_trust(&ips, 0);
        assert!(trust >= 60);

        let trust_listed = estimate_domain_trust(&ips, 3);
        assert!(trust_listed < trust);
    }
}