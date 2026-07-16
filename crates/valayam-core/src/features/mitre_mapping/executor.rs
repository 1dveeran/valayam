use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::MitreMappingTemplate;
use chrono::Utc;
use std::collections::HashMap;

pub async fn execute(
    templates: &[MitreMappingTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
    mut findings: Vec<ScanResult>,
) -> Option<ScanResult> {
    for template in templates {
        if template.enable_mapping {
            for finding in &mut findings {
                // MVP: Add MITRE tags based on CWE mapping
                if let Some(cwe) = finding.compliance.get("cwe") {
                    match cwe.as_str() {
                        "CWE-79" | "CWE-94" | "CWE-89" | "CWE-601" => {
                            finding.compliance.insert("mitre".to_string(), "T1190 (Exploit Public-Facing Application)".to_string());
                        }
                        "CWE-287" | "CWE-798" | "CWE-522" => {
                            finding.compliance.insert("mitre".to_string(), "T1110 (Brute Force) / T1552 (Unsecured Credentials)".to_string());
                        }
                        "CWE-918" | "CWE-497" => {
                            finding.compliance.insert("mitre".to_string(), "T1596 (Search Open Technical Databases)".to_string());
                        }
                        _ => {}
                    }
                }
            }
            
            let mut compliance = HashMap::new();
            compliance.insert("reporting".to_string(), "MITRE ATT&CK Mapping Complete".to_string());
            
            return Some(ScanResult {
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: "Info".to_string(),
                target: "System".to_string(),
                payload: format!("Successfully mapped {} findings to MITRE ATT&CK techniques.", findings.len()),
                cvss_score: None,
                reference: None,
                solution: None,
                tags: Vec::new(),
                compliance,
            });
        }
    }
    None
}
