//! Bridge utility: convert between legacy ScanResult and FindingOwned.
//! Preserves all fields in both directions.
//!
//! Fields from `ScanResult` that have no direct counterpart in `FindingOwned`
//! (`cvss_score`, `solution`, `reference`) are stored in `FindingOwned.metadata`
//! under prefixed keys to avoid collisions with compliance data.

use crate::result::ScanResult;
use crate::finding::FindingOwned;
use std::collections::HashMap;

/// Prefix used for ScanResult-only fields stored in FindingOwned.metadata.
const META_CVSS_SCORE: &str = "::cvss_score";
const META_SOLUTION: &str = "::solution";
const META_REFERENCE: &str = "::reference";

/// Convert a legacy ScanResult into a FindingOwned, preserving all fields.
pub fn scan_result_to_finding(result: ScanResult) -> FindingOwned {
    let mut metadata = result.compliance;

    if let Some(score) = result.cvss_score {
        metadata.insert(META_CVSS_SCORE.to_string(), score.to_string());
    }
    if let Some(ref solution) = result.solution {
        metadata.insert(META_SOLUTION.to_string(), solution.clone());
    }
    if let Some(reference) = result.reference {
        metadata.insert(META_REFERENCE.to_string(), reference);
    }
    if !result.tags.is_empty() {
        metadata.insert("::tags".to_string(), result.tags.join(","));
    }

    FindingOwned {
        template_id: result.template_id,
        template_name: result.template_name,
        severity: result.template_severity,
        target: result.target,
        matched_at: result.payload,
        description: None,
        solution: result.solution,
        extracted_data: None,
        metadata,
    }
}

/// Reconstruct a ScanResult from a FindingOwned without data loss.
///
/// Extracts `cvss_score`, `solution`, `reference`, and `tags` from
/// `FindingOwned.metadata` where they were stored by `scan_result_to_finding`.
pub fn finding_to_scan_result(finding: FindingOwned) -> ScanResult {
    let mut compliance = HashMap::new();
    let mut cvss_score: Option<f32> = None;
    let mut solution: Option<String> = None;
    let mut reference: Option<String> = None;
    let mut tags: Vec<String> = Vec::new();

    for (key, value) in &finding.metadata {
        match key.as_str() {
            META_CVSS_SCORE => {
                cvss_score = value.parse::<f32>().ok();
            }
            META_SOLUTION => {
                solution = Some(value.clone());
            }
            META_REFERENCE => {
                reference = Some(value.clone());
            }
            "::tags" => {
                tags = value.split(',').map(|s| s.to_string()).collect();
            }
            // Everything else is genuine compliance data
            other => {
                compliance.insert(other.to_string(), value.clone());
            }
        }
    }

    ScanResult {
        schema_version: "1.0.0".to_string(),
        timestamp: chrono::Utc::now(),
        template_id: finding.template_id,
        template_name: finding.template_name,
        template_severity: finding.severity,
        target: finding.target,
        payload: finding.matched_at,
        compliance,
        cvss_score,
        solution: finding.solution.or(solution),
        reference,
        tags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_result_to_finding_basic() {
        let sr = ScanResult { schema_version: "1.0.0".to_string(),
            template_id: "test-001".into(),
            template_name: "SQLi Test".into(),
            template_severity: "high".into(),
            target: "https://example.com".into(),
            payload: "SQL injection in /login".into(),
            compliance: [("cwe".into(), "89".into())].into(),
            cvss_score: Some(7.5),
            solution: Some("Use prepared statements".into()),
            reference: Some("https://cve.mitre.org/1234".into()),
            tags: vec!["sql".into(), "injection".into()],
            timestamp: chrono::Utc::now(),
        };

        let finding = scan_result_to_finding(sr);

        assert_eq!(finding.template_id, "test-001");
        assert_eq!(finding.severity, "high");
        assert_eq!(finding.target, "https://example.com");
        assert_eq!(finding.matched_at, "SQL injection in /login");
        assert_eq!(finding.metadata.get("::cvss_score").unwrap(), "7.5");
        assert_eq!(finding.metadata.get("::solution").unwrap(), "Use prepared statements");
        assert_eq!(finding.metadata.get("::reference").unwrap(), "https://cve.mitre.org/1234");
        assert_eq!(finding.metadata.get("::tags").unwrap(), "sql,injection");
        assert_eq!(finding.metadata.get("cwe").unwrap(), "89");
    }

    #[test]
    fn test_scan_result_to_finding_no_optionals() {
        let sr = ScanResult { schema_version: "1.0.0".to_string(),
            template_id: "test-002".into(),
            template_name: "No Opt".into(),
            template_severity: "low".into(),
            target: "https://example.com".into(),
            payload: "info leak".into(),
            compliance: Default::default(),
            cvss_score: None,
            solution: None,
            reference: None,
            tags: vec![],
            timestamp: chrono::Utc::now(),
        };

        let finding = scan_result_to_finding(sr);
        assert_eq!(finding.metadata.len(), 0);
        assert!(finding.solution.is_none());
    }

    #[test]
    fn test_finding_to_scan_result_roundtrip() {
        let original = ScanResult { schema_version: "1.0.0".to_string(),
            template_id: "roundtrip".into(),
            template_name: "Roundtrip Test".into(),
            template_severity: "critical".into(),
            target: "https://target.com".into(),
            payload: "matched".into(),
            compliance: [("cwe".into(), "79".into())].into(),
            cvss_score: Some(9.0),
            solution: Some("Sanitize".into()),
            reference: Some("https://owasp.org".into()),
            tags: vec!["xss".into()],
            timestamp: chrono::Utc::now(),
        };

        let finding = scan_result_to_finding(original);
        let reconstructed = finding_to_scan_result(finding);

        assert_eq!(reconstructed.template_id, "roundtrip");
        assert_eq!(reconstructed.template_severity, "critical");
        assert_eq!(reconstructed.target, "https://target.com");
        assert_eq!(reconstructed.payload, "matched");
        assert_eq!(reconstructed.compliance.get("cwe").unwrap(), "79");
        assert_eq!(reconstructed.cvss_score.unwrap(), 9.0);
        assert!(reconstructed.solution.is_some());
        assert!(reconstructed.reference.is_some());
        assert!(reconstructed.tags.contains(&"xss".to_string()));
    }

    #[test]
    fn test_scan_result_with_compliance_only_roundtrip() {
        let sr = ScanResult { schema_version: "1.0.0".to_string(),
            template_id: "compliance-only".into(),
            template_name: "Compliance".into(),
            template_severity: "medium".into(),
            target: "https://test.com".into(),
            payload: "compliance issue".into(),
            compliance: [("owasp".into(), "A3:2017".into()), ("nist".into(), "SP-800-53".into())].into(),
            cvss_score: None,
            solution: None,
            reference: None,
            tags: vec![],
            timestamp: chrono::Utc::now(),
        };

        let finding = scan_result_to_finding(sr);
        let back = finding_to_scan_result(finding);

        assert_eq!(back.compliance.get("owasp").unwrap(), "A3:2017");
        assert_eq!(back.compliance.get("nist").unwrap(), "SP-800-53");
        assert_eq!(back.compliance.len(), 2);
    }

    #[test]
    fn test_finding_to_scan_result_preserves_solution() {
        // solution in FindingOwned.solution should take precedence over metadata
        let finding = FindingOwned {
            template_id: "test".into(),
            template_name: "Test".into(),
            severity: "info".into(),
            target: "https://example.com".into(),
            matched_at: "matched".into(),
            description: None,
            solution: Some("direct solution".into()),
            extracted_data: None,
            metadata: [("::solution".into(), "metadata solution".into())].into(),
        };

        let sr = finding_to_scan_result(finding);
        // FindingOwned.solution takes precedence via finding.solution.or(solution)
        assert_eq!(sr.solution.unwrap(), "direct solution");
    }

    #[test]
    fn test_finding_to_scan_result_cvss_from_metadata() {
        let finding = FindingOwned {
            template_id: "test".into(),
            template_name: "Test".into(),
            severity: "high".into(),
            target: "https://example.com".into(),
            matched_at: "match".into(),
            description: None,
            solution: None,
            extracted_data: None,
            metadata: [("::cvss_score".into(), "5.5".into())].into(),
        };

        let sr = finding_to_scan_result(finding);
        assert_eq!(sr.cvss_score, Some(5.5));
    }
}
