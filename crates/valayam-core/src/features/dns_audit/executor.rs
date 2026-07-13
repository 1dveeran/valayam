use crate::core::result::ScanResult;
use crate::core::variables::resolve_variables;
use crate::network::dns;
use crate::template::schema::TemplateInfo;
use super::parser::DnsRequestTemplate;
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;

/// Executes all DNS audit rules from a template.
/// Performs DNS lookups and evaluates regex matchers against the results.
pub async fn execute(
    dns_rules: &[DnsRequestTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
    variables: &HashMap<String, String>,
) -> Option<ScanResult> {
    for rule in dns_rules {
        let domain = resolve_variables(&rule.domain, variables);
        let records = dns::resolve(&domain, &rule.query_type).await;

        if records.is_empty() {
            continue;
        }

        // Join all records into a single string for matching
        let records_text = records.join("\n");

        if rule.matchers.is_empty() {
            // No matchers: any result is a finding
            return Some(ScanResult {
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: template_info.severity.clone(),
                target: domain,
                payload: format!("{} records: {}", rule.query_type, records_text),
            });
        }

        // Evaluate regex matchers against DNS results
        for matcher in &rule.matchers {
            if matcher.r#type == "regex" {
                for pattern in &matcher.regex {
                    let Ok(re) = Regex::new(pattern) else {
                        continue;
                    };
                    if re.is_match(&records_text) {
                        return Some(ScanResult {
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: template_info.severity.clone(),
                            target: domain,
                            payload: format!(
                                "DNS {} matched '{}': {}",
                                rule.query_type, pattern, records_text
                            ),
                        });
                    }
                }
            }
        }
    }

    None
}
