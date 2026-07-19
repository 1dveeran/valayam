//! Bridge utility: convert legacy ScanResult → FindingOwned.
//! Used by all plugin adapters.

use crate::core::result::ScanResult;
use crate::core::traits::FindingOwned;

/// Convert a legacy ScanResult into a FindingOwned.
pub fn scan_result_to_finding(result: ScanResult) -> FindingOwned {
    FindingOwned {
        template_id: result.template_id,
        template_name: result.template_name,
        severity: result.template_severity,
        target: result.target,
        matched_at: result.payload,
        extracted_data: None,
        metadata: result.compliance,
    }
}
