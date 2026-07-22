use crate::core::result::ScanResult;
use crate::network::http::StealthHttpClient;
use valayam_models::templates::schema::TemplateInfo;
use super::cve_sync::{self, CveFinding, CveSeverity};
use valayam_models::templates::sbom_audit::SbomAuditTemplate;
use chrono::Utc;
use std::collections::HashMap;
use tracing::{debug, warn};

/// A parsed package entry from an SBOM / manifest file.
#[derive(Debug, Clone)]
struct PackageEntry {
    name: String,
    version: Option<String>,
}

/// Attempt to parse a package.json content into package entries.
fn parse_package_json(body: &str) -> Vec<PackageEntry> {
    let mut packages = Vec::new();
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(json) => {
            // Extract from "dependencies" and "devDependencies" objects.
            if let Some(deps) = json.get("dependencies").and_then(|v| v.as_object()) {
                for (name, version_value) in deps {
                    let version = version_value.as_str().map(|s| s.trim_start_matches('^').trim_start_matches('~').to_string());
                    packages.push(PackageEntry {
                        name: name.clone(),
                        version,
                    });
                }
            }
            if let Some(dev_deps) = json.get("devDependencies").and_then(|v| v.as_object()) {
                for (name, version_value) in dev_deps {
                    let version = version_value.as_str().map(|s| s.trim_start_matches('^').trim_start_matches('~').to_string());
                    packages.push(PackageEntry {
                        name: name.clone(),
                        version,
                    });
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "Failed to parse package.json");
        }
    }
    packages
}

/// Attempt to parse a Cargo.toml content into package entries (dependencies only).
fn parse_cargo_toml(body: &str) -> Vec<PackageEntry> {
    let mut packages = Vec::new();
    match toml::from_str::<toml::Value>(body) {
        Ok(toml_value) => {
            // Extract from [dependencies] section
            if let Some(deps) = toml_value.get("dependencies").and_then(|v| v.as_table()) {
                for (name, value) in deps {
                    let version = match value {
                        toml::Value::String(s) => Some(s.clone()),
                        toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        _ => None,
                    };
                    packages.push(PackageEntry {
                        name: name.clone(),
                        version,
                    });
                }
            }
            // Extract from [dev-dependencies] section
            if let Some(deps) = toml_value.get("dev-dependencies").and_then(|v| v.as_table()) {
                for (name, value) in deps {
                    let version = match value {
                        toml::Value::String(s) => Some(s.clone()),
                        toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        _ => None,
                    };
                    packages.push(PackageEntry {
                        name: name.clone(),
                        version,
                    });
                }
            }
            // Extract from [build-dependencies] section
            if let Some(deps) = toml_value.get("build-dependencies").and_then(|v| v.as_table()) {
                for (name, value) in deps {
                    let version = match value {
                        toml::Value::String(s) => Some(s.clone()),
                        toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        _ => None,
                    };
                    packages.push(PackageEntry {
                        name: name.clone(),
                        version,
                    });
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "Failed to parse Cargo.toml");
        }
    }
    packages
}

/// Attempt to parse a requirements.txt content into package entries.
fn parse_requirements_txt(body: &str) -> Vec<PackageEntry> {
    let mut packages = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        // Skip comments, blank lines, and options
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        // Handle lines like: package==1.2.3 or package>=1.2.3
        let separators = &["==", ">=", "<=", "!=", "~=", ">", "<"];
        if let Some((name, version)) = separators.iter().find_map(|sep| {
            line.split_once(sep).map(|(n, v)| (n.trim(), v.trim()))
        }) {
            // Remove any inline comments from version
            let version = version.split('#').next().unwrap_or(version).trim();
            let version = version.split(" --").next().unwrap_or(version).trim();
            packages.push(PackageEntry {
                name: name.to_string(),
                version: Some(version.to_string()),
            });
        } else {
            // No version specified
            packages.push(PackageEntry {
                name: line.to_string(),
                version: None,
            });
        }
    }
    packages
}

/// Parse SBOM content based on file type.
fn parse_packages(body: &str, file_type: &str) -> Vec<PackageEntry> {
    let file_lower = file_type.to_ascii_lowercase();

    if file_lower.contains("package.json") {
        parse_package_json(body)
    } else if file_lower.contains("cargo.toml") {
        parse_cargo_toml(body)
    } else if file_lower.contains("requirements.txt") {
        parse_requirements_txt(body)
    } else {
        // Try generic detection by content
        let trimmed = body.trim();
        if trimmed.starts_with('{') {
            // Try as JSON (package.json style)
            let pkgs = parse_package_json(body);
            if !pkgs.is_empty() {
                return pkgs;
            }
        }
        if trimmed.starts_with('[') {
            // Could be a TOML table but also starts with [ (Cargo.toml)
            let pkgs = parse_cargo_toml(body);
            if !pkgs.is_empty() {
                return pkgs;
            }
        }
        // Fallback to pip-style parsing
        parse_requirements_txt(body)
    }
}

/// Determine ecosystem from file type.
fn detect_ecosystem(file_type: &str) -> &'static str {
    cve_sync::detect_ecosystem_from_file(file_type)
}

/// Aggregate CVE findings into a scan result payload.
fn build_cve_payload(
    all_findings: &HashMap<String, Vec<CveFinding>>,
    package_count: usize,
) -> (String, u8) {
    let total_cves: usize = all_findings.values().map(|v| v.len()).sum();

    if total_cves == 0 {
        return (
            format!(
                "SBOM audit completed: {} package(s) analyzed, no known CVEs found.",
                package_count
            ),
            0,
        );
    }

    let critical_count: usize = all_findings
        .values()
        .flatten()
        .filter(|f| f.severity == CveSeverity::Critical)
        .count();
    let high_count: usize = all_findings
        .values()
        .flatten()
        .filter(|f| f.severity == CveSeverity::High)
        .count();
    let medium_count: usize = all_findings
        .values()
        .flatten()
        .filter(|f| f.severity == CveSeverity::Medium)
        .count();

    // Find max severity
    let max_sev = all_findings
        .values()
        .flatten()
        .map(|f| f.severity.clone())
        .max_by(|a, b| a.rank().cmp(&b.rank()))
        .unwrap_or(CveSeverity::None);

    // Build per-package summary lines
    let mut detail_lines: Vec<String> = Vec::new();
    for (pkg, findings) in all_findings {
        if !findings.is_empty() {
            detail_lines.push(cve_sync::findings_to_summary(pkg, findings));
            // Show top CVEs for each package
            for finding in findings.iter().take(3) {
                let score_str = finding
                    .cvss_score
                    .map(|s| format!(" (CVSS: {:.1})", s))
                    .unwrap_or_default();
                detail_lines.push(format!(
                    "  - {}: {}{}",
                    finding.cve_id,
                    finding.summary.as_deref().unwrap_or("No summary"),
                    score_str,
                ));
            }
        }
    }

    let severity_score: u8 = match max_sev {
        CveSeverity::Critical => 100,
        CveSeverity::High => 70,
        CveSeverity::Medium => 40,
        CveSeverity::Low => 15,
        CveSeverity::None => 0,
    };

    let payload = format!(
        "SBOM audit: {} package(s) analyzed, {} CVE(s) found ({} Critical, {} High, {} Medium). Max severity: {}.\n\n{}",
        package_count,
        total_cves,
        critical_count,
        high_count,
        medium_count,
        max_sev.as_str(),
        detail_lines.join("\n"),
    );

    (payload, severity_score)
}

/// Build a severity string from numeric score.
fn severity_score_to_str(score: u8) -> &'static str {
    match score {
        0 => "Info",
        1..=20 => "Low",
        21..=50 => "Medium",
        51..=75 => "High",
        76..=100 => "Critical",
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Execute SBOM audit against a target URL.
///
/// Fetches the manifest file (package.json, Cargo.toml, requirements.txt, etc.),
/// parses the dependency list, queries OSV.dev for known vulnerabilities,
/// and returns a `ScanResult` with CVE findings.
pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[SbomAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);
        let base = host.trim_end_matches('/');
        let file_type = template.r#type.trim_start_matches('/');
        let url = format!("{}/{}", base, file_type);

        debug!(url = %url, file_type = %file_type, "Fetching SBOM file");

        // Fetch the manifest file
        let resp = match client.send_request("GET", &url, None, None).await {
            Ok(r) => r,
            Err(e) => {
                warn!(url = %url, error = %e, "Failed to fetch SBOM file");
                continue;
            }
        };

        if !resp.status().is_success() {
            debug!(url = %url, status = %resp.status(), "SBOM file not found");
            continue;
        }

        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                warn!(url = %url, error = %e, "Failed to read SBOM file body");
                continue;
            }
        };

        // Parse the packages from the manifest
        let packages = parse_packages(&body, file_type);
        if packages.is_empty() {
            // File was fetched but couldn't be parsed — return a minimal finding
            let mut compliance = HashMap::new();
            compliance.insert("recon".to_string(), "SBOM".to_string());

            return Some(ScanResult { schema_version: "1.0.0".to_string(),
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: "Info".to_string(),
                target: url.clone(),
                payload: format!(
                    "Exposed SBOM file detected at: {} ({} bytes) but no dependencies could be parsed.",
                    url,
                    body.len()
                ),
                cvss_score: None,
                reference: None,
                solution: Some("Remove or restrict access to the manifest/SBOM file if it is not intended for public access.".to_string()),
                tags: vec!["sbom".to_string(), "exposure".to_string(), "info".to_string()],
                compliance,
            });
        }

        debug!(
            url = %url,
            package_count = packages.len(),
            "Parsed packages from SBOM file"
        );

        // Query OSV.dev for each package
        let ecosystem = detect_ecosystem(file_type);
        let batch: Vec<(&str, Option<&str>, Option<&str>)> = packages
            .iter()
            .map(|p| {
                (
                    p.name.as_str(),
                    if ecosystem.is_empty() { None } else { Some(ecosystem) },
                    p.version.as_deref(),
                )
            })
            .collect();

        let all_findings = cve_sync::query_osv_batch(&batch).await;

        // Build the result
        let (payload, severity_score) = build_cve_payload(&all_findings, packages.len());
        let severity = severity_score_to_str(severity_score);

        let mut compliance = HashMap::new();
        compliance.insert("recon".to_string(), "SBOM".to_string());
        if severity_score >= 40 {
            compliance.insert(
                "standard".to_string(),
                "OWASP Top 10 A06:2021 - Vulnerable and Outdated Components".to_string(),
            );
        }

        let cvss = if severity_score > 0 {
            Some((severity_score as f32) / 10.0)
        } else {
            None
        };

        let mut tags = vec![
            "sbom".to_string(),
            "cve".to_string(),
            format!("packages-{}", packages.len()),
        ];

        if all_findings.values().any(|v| !v.is_empty()) {
            tags.push("vulnerable".to_string());
            tags.push(format!("severity-{}", severity.to_ascii_lowercase()));
        }

        let reference = if all_findings.values().any(|v| v.iter().any(|f| !f.reference_urls.is_empty())) {
            Some("https://osv.dev/ | https://nvd.nist.gov/".to_string())
        } else {
            None
        };

        let solution = if all_findings.values().any(|v| !v.is_empty()) {
            Some(
                "Update affected packages to their latest patched versions. \
                 Review and remediate Critical/High severity CVEs as a priority. \
                 Consider integrating automated dependency scanning in CI/CD."
                    .to_string(),
            )
        } else {
            None
        };

        return Some(ScanResult { schema_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            template_id: template_id.to_string(),
            template_name: template_info.name.clone(),
            template_severity: severity.to_string(),
            target: url.clone(),
            payload,
            cvss_score: cvss,
            reference,
            solution,
            tags,
            compliance,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_package_json() {
        let body = r#"{
            "name": "test-app",
            "dependencies": {
                "express": "^4.18.0",
                "lodash": "~4.17.21"
            },
            "devDependencies": {
                "typescript": "^5.0.0"
            }
        }"#;
        let packages = parse_package_json(body);
        assert_eq!(packages.len(), 3);
        assert!(packages.iter().any(|p| p.name == "express" && p.version.as_deref() == Some("4.18.0")));
        assert!(packages.iter().any(|p| p.name == "lodash" && p.version.as_deref() == Some("4.17.21")));
        assert!(packages.iter().any(|p| p.name == "typescript"));
    }

    #[test]
    fn test_parse_cargo_toml() {
        let body = r#"
[package]
name = "test-crate"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
regex = "1.10"

[dev-dependencies]
tempfile = "3.0"
"#;
        let packages = parse_cargo_toml(body);
        assert_eq!(packages.len(), 4);
        assert!(packages.iter().any(|p| p.name == "serde"));
        assert!(packages.iter().any(|p| p.name == "tokio"));
        assert!(packages.iter().any(|p| p.name == "tempfile"));
    }

    #[test]
    fn test_parse_requirements_txt() {
        let body = "requests==2.31.0\nflask>=2.3.0\n# comment\nnumpy\nclick<=8.1.0";
        let packages = parse_requirements_txt(body);
        assert_eq!(packages.len(), 4);
        assert!(packages.iter().any(|p| p.name == "requests" && p.version.as_deref() == Some("2.31.0")));
        assert!(packages.iter().any(|p| p.name == "numpy" && p.version.is_none()));
    }

    #[test]
    fn test_parse_packages_auto_detect_json() {
        let body = r#"{"dependencies": {"express": "^4.0.0"}}"#;
        let packages = parse_packages(body, "package.json");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "express");
    }

    #[test]
    fn test_severity_score_to_str() {
        assert_eq!(severity_score_to_str(0), "Info");
        assert_eq!(severity_score_to_str(10), "Low");
        assert_eq!(severity_score_to_str(30), "Medium");
        assert_eq!(severity_score_to_str(60), "High");
        assert_eq!(severity_score_to_str(90), "Critical");
    }
}