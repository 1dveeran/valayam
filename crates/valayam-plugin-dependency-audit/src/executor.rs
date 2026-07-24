use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use std::path::Path;
use valayam_models::templates::dependency_audit::DependencyAuditTemplate;
use super::extractor::extract_dependencies;
use super::vuln_db::{ApiVulnDb, LocalVulnDb};

pub async fn execute(
    templates: &[DependencyAuditTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
    // Only return the first found critical vulnerability for now
    for template in templates {
        let dir_path = Path::new(&template.target_repo);
        if !dir_path.exists() { continue; }

        let lockfiles = vec![
            dir_path.join("Cargo.lock"),
            dir_path.join("package-lock.json"),
        ];

        let mode = template.cve_mode.as_deref().unwrap_or("api");

        // Prepare our CVE checker if possible
        let api_checker = if mode == "api" {
            template.api_url.as_ref().map(|url| ApiVulnDb::new(url.clone(), reqwest::Client::new()))
        } else {
            None
        };

        let local_checker = if mode == "local" {
            template.local_db_path.as_ref().map(|path| LocalVulnDb::new(path.clone()))
        } else {
            None
        };

        for lockfile in lockfiles {
            if lockfile.exists() {
                let deps = extract_dependencies(&lockfile);
                for dep in deps {
                    let mut vulns = Vec::new();

                    if let Some(ref api) = api_checker {
                        vulns = api.check_package(&dep.ecosystem, &dep.name, &dep.version).await;
                    } else if let Some(ref local) = local_checker {
                        vulns = local.check_package(&dep.ecosystem, &dep.name, &dep.version);
                    }

                    if !vulns.is_empty() {
                        // Return the first vulnerability found
                        let vuln = &vulns[0];
                        let mut finding = FindingOwned::from_template_and_info(
                            template_id,
                            template_meta,
                            lockfile.to_string_lossy().to_string(),
                            format!("Dependency Audit: Package {}@{} is vulnerable to {}", dep.name, dep.version, vuln.cve_id),
                        );
                        finding.severity = vuln.severity.clone();
                        return Some(finding);
                    }
                }
            }
        }
    }
    None
}
