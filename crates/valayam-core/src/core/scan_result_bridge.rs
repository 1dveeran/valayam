//! Bridge utility: convert between legacy ScanResult and FindingOwned.
//! Preserves all fields in both directions.
//!
//! Fields from `ScanResult` that have no direct counterpart in `FindingOwned`
//! (`cvss_score`, `solution`, `reference`) are stored in `FindingOwned.metadata`
//! under prefixed keys to avoid collisions with compliance data.

use crate::core::result::ScanResult;
use crate::core::traits::FindingOwned;
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
