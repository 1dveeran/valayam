use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use valayam_models::templates::remediation_gen::RemediationGenTemplate;

pub async fn execute(
    templates: &[RemediationGenTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
    mut findings: Vec<FindingOwned>,
) -> Option<FindingOwned> {
    for template in templates {
        if template.output_format == "markdown" {
            for finding in &mut findings {
                // MVP: Add remediation steps based on CWE
                if let Some(cwe) = finding.metadata.get("cwe") {
                    let steps = match cwe.as_str() {
                        "CWE-601" => "Validate URLs against a strict allowlist before passing to window.location.",
                        "CWE-798" | "CWE-522" => "Revoke the exposed credentials immediately and rotate keys. Use a secure secrets manager.",
                        "CWE-16" | "CWE-1104" => "Update the misconfigured or deprecated component to a secure version/configuration.",
                        "CWE-918" => "Implement strict allowlisting for outgoing requests and disable metadata endpoints if not needed.",
                        "CWE-287" => "Ensure your JWT library enforces strict signature verification and rejects 'alg: none'.",
                        _ => "Review the finding and apply standard secure coding practices.",
                    };
                    finding.metadata.insert("remediation".to_string(), steps.to_string());
                }
            }

            let mut finding = FindingOwned::from_template_and_info(
                template_id,
                template_meta,
                "System".to_string(),
                format!("Successfully mapped {} findings to actionable remediation steps.", findings.len()),
            );
            finding.severity = "Info".to_string();
            finding.metadata.insert("reporting".to_string(), "Remediation Snippets Generated".to_string());
            return Some(finding);
        }
    }
    None
}