use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use std::fs;
use std::path::Path;
use valayam_models::templates::cicd_audit::CicdAuditTemplate;

pub async fn execute(
    templates: &[CicdAuditTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
    for template in templates {
        let dir_path = Path::new(&template.target_repo);
        if !dir_path.exists() { continue; }

        let workflows_dir = dir_path.join(".github").join("workflows");
        if workflows_dir.exists() && workflows_dir.is_dir() {
            if let Ok(entries) = fs::read_dir(workflows_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(ext) = path.extension() {
                        if ext == "yml" || ext == "yaml" {
                            if let Ok(content) = fs::read_to_string(&path) {
                                // Check for dangerous pull_request_target which can lead to pwn request
                                if content.contains("pull_request_target:") && content.contains("checkout") {
                                    let mut finding = FindingOwned::from_template_and_info(
                                        template_id,
                                        template_meta,
                                        path.to_string_lossy().to_string(),
                                        "CI/CD Audit: GitHub Action workflow uses 'pull_request_target' with 'actions/checkout', which is vulnerable to malicious PRs (Pwn Request).".to_string(),
                                    );
                                    finding.severity = "High".to_string();
                                    return Some(finding);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}