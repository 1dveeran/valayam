use crate::core::result::ScanResult;
use valayam_models::templates::schema::TemplateInfo;
use valayam_models::templates::remediation_gen::RemediationGenTemplate;
use chrono::Utc;
use std::collections::HashMap;

pub async fn execute(
    templates: &[RemediationGenTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
    mut findings: Vec<ScanResult>,
) -> Option<ScanResult> {
    for template in templates {
        if template.output_format == "markdown" {
            for finding in &mut findings {
                // MVP: Add remediation steps based on CWE
                if let Some(cwe) = finding.compliance.get("cwe") {
                    let steps = match cwe.as_str() {
                        "CWE-601" => "Validate URLs against a strict allowlist before passing to window.location.",
                        "CWE-798" | "CWE-522" => "Revoke the exposed credentials immediately and rotate keys. Use a secure secrets manager.",
                        "CWE-16" | "CWE-1104" => "Update the misconfigured or deprecated component to a secure version/configuration.",
                        "CWE-918" => "Implement strict allowlisting for outgoing requests and disable metadata endpoints if not needed.",
                        "CWE-287" => "Ensure your JWT library enforces strict signature verification and rejects 'alg: none'.",
                        _ => "Review the finding and apply standard secure coding practices.",
                    };
                    finding.compliance.insert("remediation".to_string(), steps.to_string());
                }
            }
            
            let mut compliance = HashMap::new();
            compliance.insert("reporting".to_string(), "Remediation Snippets Generated".to_string());
            
            return Some(ScanResult { schema_version: "1.0.0".to_string(),
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: "Info".to_string(),
                target: "System".to_string(),
                payload: format!("Successfully mapped {} findings to actionable remediation steps.", findings.len()),
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
