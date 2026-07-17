/// CVE synchronization module using the OSV.dev API.
///
/// OSV.dev is a vulnerability database that maps open-source packages to
/// CVEs using a schema based on the Open Source Vulnerability format.
/// API endpoint: https://api.osv.dev/v1/query
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, warn};

/// A request to the OSV.dev /v1/query endpoint.
#[derive(Debug, Serialize)]
struct OsvQueryRequest {
    package: OsvPackage,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecosystem: Option<String>,
}

/// A vulnerability entry returned by the OSV.dev API.
#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    modified: Option<String>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: Option<Value>,
    #[serde(default)]
    references: Vec<OsvReference>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    #[serde(rename = "type")]
    ref_type: String,
    url: String,
}

/// Response from OSV.dev /v1/query containing a list of vulnerabilities.
#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

/// A single CVE finding for a given package.
#[derive(Debug, Clone)]
pub struct CveFinding {
    pub cve_id: String,
    pub package_name: String,
    pub ecosystem: Option<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub cvss_score: Option<f32>,
    pub severity: CveSeverity,
    pub reference_urls: Vec<String>,
}

/// Normalized severity for a CVE finding.
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum CveSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl CveSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            CveSeverity::None => "None",
            CveSeverity::Low => "Low",
            CveSeverity::Medium => "Medium",
            CveSeverity::High => "High",
            CveSeverity::Critical => "Critical",
        }
    }

    /// Return a numeric rank for comparison (higher = more severe).
    pub fn rank(&self) -> u8 {
        match self {
            CveSeverity::None => 0,
            CveSeverity::Low => 1,
            CveSeverity::Medium => 2,
            CveSeverity::High => 3,
            CveSeverity::Critical => 4,
        }
    }
}

/// Infer the ecosystem name from a package name or SBOM file type.
pub fn detect_ecosystem_from_file(file_name: &str) -> &'static str {
    let lower = file_name.to_ascii_lowercase();
    if lower.ends_with("package.json") || lower.ends_with("package-lock.json") || lower.ends_with("yarn.lock") {
        "npm"
    } else if lower.ends_with("cargo.toml") || lower.ends_with("cargo.lock") {
        "crates.io"
    } else if lower.ends_with("requirements.txt") || lower.ends_with("setup.py") || lower.ends_with("pyproject.toml") {
        "PyPI"
    } else if lower.ends_with("pom.xml") || lower.ends_with("build.gradle") || lower.ends_with("gradle.lockfile") {
        "Maven"
    } else if lower.ends_with("go.mod") || lower.ends_with("go.sum") {
        "Go"
    } else if lower.ends_with("gemfile") || lower.ends_with("gemfile.lock") {
        "RubyGems"
    } else if lower.ends_with("composer.json") || lower.ends_with("composer.lock") {
        "Packagist"
    } else if lower.ends_with("nuget.config") || lower.ends_with("packages.config") || lower.ends_with(".csproj") {
        "NuGet"
    } else {
        // Generic — let OSV.dev figure it out
        ""
    }
}

/// Map an OSV severity entry to a CVSS score (0.0-10.0).
fn parse_osv_severity_to_cvss(severities: &[OsvSeverity]) -> Option<f32> {
    for sev in severities {
        match sev.severity_type.to_ascii_lowercase().as_str() {
            "cvss_v3" | "cvss" => {
                // Scores look like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                // Extract the base score from the vector or try to parse directly.
                if let Ok(score) = sev.score.parse::<f32>() {
                    if (0.0..=10.0).contains(&score) {
                        return Some(score);
                    }
                }
                // If not a simple float, could be a CVSS vector string.
                // Try to find "CVSS:3.x/..." base score from a known pattern.
                // For now, fall back to the std outcome if any.
            }
            _ => {}
        }
    }
    None
}

/// Map a CVSS score (0.0-10.0) to a CveSeverity.
fn cvss_to_severity(score: Option<f32>) -> CveSeverity {
    match score {
        None => CveSeverity::None,
        Some(s) if s >= 9.0 => CveSeverity::Critical,
        Some(s) if s >= 7.0 => CveSeverity::High,
        Some(s) if s >= 4.0 => CveSeverity::Medium,
        Some(s) if s >= 0.1 => CveSeverity::Low,
        _ => CveSeverity::None,
    }
}

/// Query the OSV.dev API for vulnerabilities affecting a given package.
///
/// # Arguments
/// * `package_name` - The name of the package (e.g. "lodash", "serde")
/// * `ecosystem` - Optional ecosystem hint (e.g. "npm", "crates.io", "PyPI")
/// * `version` - Optional specific version to check (e.g. "1.2.3")
///
/// # Returns
/// A vector of `CveFinding` for all matching vulnerabilities.
pub async fn query_osv(
    package_name: &str,
    ecosystem: Option<&str>,
    version: Option<&str>,
) -> Vec<CveFinding> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("Valayam-Security-Scanner/0.1")
        .build();

    let client = match client {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Failed to build reqwest client for OSV query");
            return Vec::new();
        }
    };

    let request_body = OsvQueryRequest {
        package: OsvPackage {
            name: package_name.to_string(),
            ecosystem: ecosystem.map(|s| s.to_string()),
        },
        version: version.map(|s| s.to_string()),
    };

    let url = "https://api.osv.dev/v1/query";
    debug!(
        package = %package_name,
        ecosystem = ?ecosystem,
        version = ?version,
        "Querying OSV.dev for vulnerabilities"
    );

    let response = match client.post(url).json(&request_body).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(
                package = %package_name,
                error = %e,
                "OSV.dev API request failed"
            );
            return Vec::new();
        }
    };

    if !response.status().is_success() {
        warn!(
            package = %package_name,
            status = %response.status(),
            "OSV.dev returned non-success status"
        );
        return Vec::new();
    }

    let query_response: OsvQueryResponse = match response.json().await {
        Ok(r) => r,
        Err(e) => {
            warn!(
                package = %package_name,
                error = %e,
                "Failed to parse OSV.dev response"
            );
            return Vec::new();
        }
    };

    let mut findings: Vec<CveFinding> = Vec::new();

    for vuln in query_response.vulns {
        let cvss_score = parse_osv_severity_to_cvss(&vuln.severity);
        let severity = cvss_to_severity(cvss_score);

        let references: Vec<String> = vuln
            .references
            .iter()
            .map(|r| r.url.clone())
            .collect();

        let summary = vuln.summary.or_else(|| vuln.details.clone());

        findings.push(CveFinding {
            cve_id: vuln.id.clone(),
            package_name: package_name.to_string(),
            ecosystem: ecosystem.map(|s| s.to_string()),
            summary,
            details: vuln.details.clone(),
            cvss_score,
            severity,
            reference_urls: references,
        });
    }

    debug!(
        package = %package_name,
        count = findings.len(),
        "OSV.dev query completed"
    );

    findings
}

/// Query multiple packages against OSV.dev concurrently.
///
/// # Arguments
/// * `packages` - A list of (package_name, ecosystem, version) tuples.
///
/// # Returns
/// A HashMap mapping package name to its CVE findings.
pub async fn query_osv_batch(
    packages: &[(&str, Option<&str>, Option<&str>)],
) -> HashMap<String, Vec<CveFinding>> {
    use futures::future::join_all;

    let handles: Vec<_> = packages
        .iter()
        .map(|(name, ecosystem, version)| {
            let name = name.to_string();
            let ecosystem = ecosystem.map(|s| s.to_string());
            let version = version.map(|s| s.to_string());
            tokio::spawn(async move {
                let findings = query_osv(
                    &name,
                    ecosystem.as_deref(),
                    version.as_deref(),
                )
                .await;
                (name, findings)
            })
        })
        .collect();

    let results = join_all(handles).await;
    let mut output: HashMap<String, Vec<CveFinding>> = HashMap::new();

    for result in results {
        match result {
            Ok((name, findings)) => {
                output.insert(name, findings);
            }
            Err(e) => {
                warn!(error = %e, "OSV batch query task failed");
            }
        }
    }

    output
}

/// Check if any CVE has severity at least the given threshold.
pub fn has_severity_at_least(findings: &[CveFinding], threshold: CveSeverity) -> bool {
    findings
        .iter()
        .any(|f| f.severity.rank() >= threshold.rank())
}

/// Aggregate the highest severity level across all findings.
pub fn max_severity(findings: &[CveFinding]) -> CveSeverity {
    findings
        .iter()
        .map(|f| f.severity.clone())
        .max_by(|a, b| a.rank().cmp(&b.rank()))
        .unwrap_or(CveSeverity::None)
}

/// Convert a list of CveFindings to a human-readable summary string.
pub fn findings_to_summary(package_name: &str, findings: &[CveFinding]) -> String {
    if findings.is_empty() {
        return format!("No known vulnerabilities for package '{}'.", package_name);
    }

    let max_sev = max_severity(findings);
    let critical_count = findings.iter().filter(|f| f.severity == CveSeverity::Critical).count();
    let high_count = findings.iter().filter(|f| f.severity == CveSeverity::High).count();
    let medium_count = findings.iter().filter(|f| f.severity == CveSeverity::Medium).count();
    let low_count = findings.iter().filter(|f| f.severity == CveSeverity::Low).count();

    format!(
        "Package '{}': {} known CVE(s) found ({} Critical, {} High, {} Medium, {} Low). Max severity: {}.",
        package_name,
        findings.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        max_sev.as_str(),
    )
}

/// Backup sync stub — kept for compatibility.
pub async fn sync_cve_db() {
    // The real CVE sync is delegated to `query_osv` / `query_osv_batch`
    // which queries OSV.dev per-package at audit time (online mode).
    // This function is a no-op; offline CVE database sync is left for a future
    // enhancement.
    debug!("CVE sync: using live OSV.dev API queries (no local DB)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ecosystem() {
        assert_eq!(detect_ecosystem_from_file("package.json"), "npm");
        assert_eq!(detect_ecosystem_from_file("Cargo.toml"), "crates.io");
        assert_eq!(detect_ecosystem_from_file("requirements.txt"), "PyPI");
        assert_eq!(detect_ecosystem_from_file("unknown.file"), "");
    }

    #[test]
    fn test_cvss_to_severity() {
        assert_eq!(cvss_to_severity(Some(9.5)), CveSeverity::Critical);
        assert_eq!(cvss_to_severity(Some(7.5)), CveSeverity::High);
        assert_eq!(cvss_to_severity(Some(5.0)), CveSeverity::Medium);
        assert_eq!(cvss_to_severity(Some(2.0)), CveSeverity::Low);
        assert_eq!(cvss_to_severity(None), CveSeverity::None);
    }

    #[test]
    fn test_severity_ranking() {
        assert!(CveSeverity::Critical.rank() > CveSeverity::High.rank());
        assert!(CveSeverity::High.rank() > CveSeverity::Medium.rank());
        assert!(CveSeverity::Medium.rank() > CveSeverity::Low.rank());
        assert!(CveSeverity::Low.rank() > CveSeverity::None.rank());
    }

    #[test]
    fn test_findings_to_summary_empty() {
        let summary = findings_to_summary("test-pkg", &[]);
        assert!(summary.contains("No known vulnerabilities"));
    }

    #[test]
    fn test_findings_to_summary_with_findings() {
        let findings = vec![CveFinding {
            cve_id: "CVE-2024-0001".to_string(),
            package_name: "test-pkg".to_string(),
            ecosystem: Some("npm".to_string()),
            summary: Some("Test vuln".to_string()),
            details: None,
            cvss_score: Some(9.0),
            severity: CveSeverity::Critical,
            reference_urls: vec![],
        }];
        let summary = findings_to_summary("test-pkg", &findings);
        assert!(summary.contains("1 known CVE"));
        assert!(summary.contains("Critical"));
    }
}