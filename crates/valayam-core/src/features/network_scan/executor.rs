use crate::core::result::ScanResult;
use crate::network::tcp;
use crate::network::udp;
use crate::template::schema::TemplateInfo;
use super::parser::NetworkRequestTemplate;
use chrono::Utc;
use regex::bytes::Regex;

/// Executes all network (TCP) scan rules from a template against the target.
///
/// Supports two modes:
/// - **No matchers**: Any open port is a finding.
/// - **With banner matchers**: Grabs the service banner and evaluates regex matchers.
pub async fn execute(
    _target_url: &str,
    target_host: &str,
    network_rules: &[NetworkRequestTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for net_rule in network_rules {
        let host_to_scan = net_rule.host.replace("{{Hostname}}", target_host);
        
        let port_results = if net_rule.protocol.to_lowercase() == "udp" {
            udp::scan_ports(
                &host_to_scan,
                &net_rule.ports,
                net_rule.banner_timeout_ms,
            )
            .await
        } else {
            tcp::scan_ports(
                &host_to_scan,
                &net_rule.ports,
                net_rule.banner_timeout_ms,
            )
            .await
        };

        if net_rule.matchers.is_empty() {
            // No matchers: any open port is a finding
            if let Some(first) = port_results.into_iter().next() {
                let payload = match &first.banner {
                    Some(b) => format!("Port {} open — Banner: {}", first.port, b.trim()),
                    None => format!("Port {} open", first.port),
                };
                return Some(ScanResult {
                    timestamp: Utc::now(),
                    template_id: template_id.to_string(),
                    template_name: template_info.name.clone(),
                    template_severity: template_info.severity.clone(),
                    target: host_to_scan,
                    payload,
                });
            }
        } else {
            // With matchers: evaluate regex against banners
            for port_result in &port_results {
                let banner_text = port_result
                    .banner
                    .as_deref()
                    .unwrap_or("");

                for matcher in &net_rule.matchers {
                    if matcher.r#type == "regex" && matcher.part == "banner" {
                        for pattern in &matcher.regex {
                            let Ok(re) = Regex::new(pattern) else {
                                continue;
                            };
                            if re.is_match(banner_text.as_bytes()) {
                                return Some(ScanResult {
                                    timestamp: Utc::now(),
                                    template_id: template_id.to_string(),
                                    template_name: template_info.name.clone(),
                                    template_severity: template_info.severity.clone(),
                                    target: host_to_scan,
                                    payload: format!(
                                        "Port {} matched '{}' — Banner: {}",
                                        port_result.port,
                                        pattern,
                                        banner_text.trim()
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    None
}
