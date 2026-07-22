use crate::core::result::ScanResult;
use valayam_models::templates::schema::TemplateInfo;
use chrono::Utc;
use std::path::Path;
use valayam_models::templates::dependency_audit::DependencyAuditTemplate;
use super::extractor::extract_dependencies;
use super::vuln_db::{ApiVulnDb, LocalVulnDb};

pub async fn execute(
    templates: &[DependencyAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
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
                        return Some(ScanResult { schema_version: "1.0.0".to_string(),
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: vuln.severity.clone(),
                            target: lockfile.to_string_lossy().to_string(),
                            payload: format!("Dependency Audit: Package {}@{} is vulnerable to {}", dep.name, dep.version, vuln.cve_id),
                            cvss_score: None,
                            reference: None,
                            solution: None,
                            tags: Vec::new(),
                            compliance: Default::default(),
                        });
                    }
                }
            }
        }
    }
    None
}
