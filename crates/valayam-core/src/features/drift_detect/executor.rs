use valayam_models::finding::FindingOwned;
use crate::network::http::StealthHttpClient;
use valayam_models::TemplateMetadata;
use valayam_models::templates::drift_detect::DriftDetectTemplate;
use super::state::{load_state, save_state, ScanState};
use std::collections::HashSet;
use tracing::{debug, info, warn};

/// Map a sensitivity string to a numeric threshold.
/// Higher numbers mean more types of drift are reported.
fn sensitivity_level(sensitivity: &str) -> u8 {
    match sensitivity.to_lowercase().as_str() {
        "low" => 1,
        "high" => 3,
        _ => 2, // "medium" (default)
    }
}

/// Generate a structural hash from response headers for drift comparison.
/// Sorts header keys alphabetically and creates a hash of "key:value" pairs.
fn generate_headers_hash(headers: &reqwest::header::HeaderMap) -> String {
    let mut header_entries: Vec<String> = Vec::new();
    for (key, value) in headers.iter() {
        if let Ok(val_str) = value.to_str() {
            header_entries.push(format!("{}:{}", key.as_str(), val_str));
        }
    }
    header_entries.sort();
    let summary = header_entries.join("|");
    format!("{:x}", md5::compute(summary.as_bytes()))
}

/// Compare a current state snapshot against a stored baseline and produce a list of
/// human-readable drift descriptions. Which checks are performed depends on the
/// configured sensitivity level.
fn detect_drift(
    current: &ScanState,
    baseline: &ScanState,
    sensitivity: &str,
) -> Vec<String> {
    let level = sensitivity_level(sensitivity);
    let mut diffs: Vec<String> = Vec::new();

    // Level 1+ checks: status code and endpoint/port changes
    if level >= 1 {
        // HTTP status code drift
        if current.response_status != baseline.response_status {
            diffs.push(format!(
                "HTTP status code changed: {} -> {}",
                baseline.response_status.map_or(0, |s| s),
                current.response_status.map_or(0, |s| s),
            ));
        }

        // Endpoint drift: list added / removed endpoints
        let old_endpoints: HashSet<&str> =
            baseline.endpoints_discovered.iter().map(|s| s.as_str()).collect();
        let new_endpoints: HashSet<&str> =
            current.endpoints_discovered.iter().map(|s| s.as_str()).collect();

        let added: Vec<String> = new_endpoints
            .difference(&old_endpoints)
            .map(|s| (*s).to_string())
            .collect();
        let removed: Vec<String> = old_endpoints
            .difference(&new_endpoints)
            .map(|s| (*s).to_string())
            .collect();

        if !added.is_empty() {
            diffs.push(format!("New endpoints discovered: {}", added.join(", ")));
        }
        if !removed.is_empty() {
            diffs.push(format!(
                "Endpoints no longer available: {}",
                removed.join(", ")
            ));
        }

        // Port drift
        let old_ports: HashSet<u16> = baseline.ports_open.iter().copied().collect();
        let new_ports: HashSet<u16> = current.ports_open.iter().copied().collect();

        let ports_added: Vec<u16> = new_ports.difference(&old_ports).copied().collect();
        let ports_removed: Vec<u16> = old_ports.difference(&new_ports).copied().collect();

        if !ports_added.is_empty() {
            diffs.push(format!("New open ports: {:?}", ports_added));
        }
        if !ports_removed.is_empty() {
            diffs.push(format!("Ports no longer open: {:?}", ports_removed));
        }
    }

    // Level 2+ checks: body hash drift
    if level >= 2 && current.response_body_hash != baseline.response_body_hash {
        diffs.push(format!(
            "Response body signature changed: old_hash={}, new_hash={}",
            baseline.response_body_hash.as_deref().unwrap_or("none"),
            current.response_body_hash.as_deref().unwrap_or("none"),
        ));
    }

    // Level 3 checks: header structure drift
    if level >= 3 && current.response_headers_hash != baseline.response_headers_hash {
        diffs.push("Response header structure changed".to_string());
    }

    diffs
}

/// Execute drift detection against a target.
///
/// For each template, this function:
/// 1. Sends an HTTP request to the target URL
/// 2. Generates a state signature (body hash, header hash, status code)
/// 3. Loads the stored baseline state for the given `baseline_id`
/// 4. Compares current vs. baseline and reports any differences
/// 5. Saves the current state as the new baseline for the next scan
///
/// If no baseline exists yet, the current state is saved and `None` is returned
/// (first scan acts as baseline seeding).
pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[DriftDetectTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);
        let backend = template.storage_backend.clone();
        let baseline_id = &template.baseline_id;
        let sensitivity = &template.sensitivity;

        debug!(
            target = %host,
            baseline_id = %baseline_id,
            sensitivity = %sensitivity,
            "Executing drift detection"
        );

        // Send request to current target
        let resp = match client.send_request("GET", &host, None, None).await {
            Ok(r) => r,
            Err(e) => {
                warn!(target = %host, error = %e, "Failed to send drift detection request");
                continue;
            }
        };

        let status = resp.status().as_u16();
        let headers_hash = generate_headers_hash(resp.headers());
        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    target = %host,
                    error = %e,
                    "Failed to read response body for drift detection"
                );
                continue;
            }
        };
        let body_hash = format!("{:x}", md5::compute(body.as_bytes()));

        // Build current state snapshot
        let current_state = ScanState {
            ports_open: Vec::new(),
            endpoints_discovered: vec![host.clone()],
            response_body_hash: Some(body_hash),
            response_headers_hash: Some(headers_hash),
            response_status: Some(status),
        };

        // Load and compare with baseline
        match load_state(baseline_id, &backend) {
            Ok(Some(baseline)) => {
                let diffs = detect_drift(&current_state, &baseline, sensitivity);

                // Persist current state as the new baseline for next comparison
                if let Err(e) = save_state(baseline_id, &current_state, &backend) {
                    warn!(
                        baseline_id = %baseline_id,
                        error = %e,
                        "Failed to persist updated baseline state"
                    );
                }

                if !diffs.is_empty() {
                    info!(
                        target = %host,
                        baseline_id = %baseline_id,
                        changes = diffs.len(),
                        "Drift detected"
                    );

                    let mut finding = FindingOwned::from_template_and_info(
                        template_id,
                        template_meta,
                        host.clone(),
                        format!(
                            "Drift detected (sensitivity: {}): {} change(s):\n{}",
                            sensitivity,
                            diffs.len(),
                            diffs.join("\n"),
                        ),
                    );
                    finding.metadata.insert("::tags".to_string(), format!("drift-detect,{}", sensitivity));
                    return Some(finding);
                } else {
                    debug!(
                        target = %host,
                        baseline_id = %baseline_id,
                        "No drift detected — state matches baseline"
                    );
                }
            }
            Ok(None) => {
                // No existing baseline — this is the first scan
                info!(
                    target = %host,
                    baseline_id = %baseline_id,
                    "No existing baseline found; creating initial baseline snapshot"
                );
                if let Err(e) = save_state(baseline_id, &current_state, &backend) {
                    warn!(
                        baseline_id = %baseline_id,
                        error = %e,
                        "Failed to save initial baseline state"
                    );
                }
            }
            Err(e) => {
                warn!(
                    baseline_id = %baseline_id,
                    error = %e,
                    "Error loading baseline state; saving current state as new baseline"
                );
                if let Err(e) = save_state(baseline_id, &current_state, &backend) {
                    warn!(
                        baseline_id = %baseline_id,
                        error = %e,
                        "Failed to save baseline after error recovery"
                    );
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_state() -> ScanState {
        ScanState {
            ports_open: vec![80, 443],
            endpoints_discovered: vec!["/api/v1/users".to_string()],
            response_body_hash: Some("abc".to_string()),
            response_headers_hash: Some("xyz".to_string()),
            response_status: Some(200),
        }
    }

    fn modified_status_state() -> ScanState {
        let mut s = sample_state();
        s.response_status = Some(500);
        s
    }

    fn modified_body_state() -> ScanState {
        let mut s = sample_state();
        s.response_body_hash = Some("def".to_string());
        s
    }

    fn modified_headers_state() -> ScanState {
        let mut s = sample_state();
        s.response_headers_hash = Some("uvw".to_string());
        s
    }

    fn added_endpoint_state() -> ScanState {
        let mut s = sample_state();
        s.endpoints_discovered.push("/api/v2/secret".to_string());
        s
    }

    fn added_port_state() -> ScanState {
        let mut s = sample_state();
        s.ports_open.push(8080);
        s
    }

    #[test]
    fn test_sensitivity_level() {
        assert_eq!(sensitivity_level("low"), 1);
        assert_eq!(sensitivity_level("medium"), 2);
        assert_eq!(sensitivity_level("high"), 3);
        assert_eq!(sensitivity_level("MEDIUM"), 2);
        assert_eq!(sensitivity_level("unknown"), 2); // fallback to medium
    }

    #[test]
    fn test_no_drift_when_identical() {
        let state = sample_state();
        let baseline = sample_state();
        let diffs = detect_drift(&state, &baseline, "medium");
        assert!(diffs.is_empty(), "Identical states should produce no drift");
    }

    #[test]
    fn test_status_drift_at_low_sensitivity() {
        let current = modified_status_state();
        let baseline = sample_state();
        let diffs = detect_drift(&current, &baseline, "low");
        assert!(
            diffs.iter().any(|d| d.contains("HTTP status code")),
            "Status code drift should be detected at low sensitivity"
        );
    }

    #[test]
    fn test_body_drift_at_medium_not_at_low() {
        let current = modified_body_state();
        let baseline = sample_state();

        let low_diffs = detect_drift(&current, &baseline, "low");
        let med_diffs = detect_drift(&current, &baseline, "medium");

        // Status is same, body hash differs
        // At low: no body hash check → should be empty
        // At medium: body hash differs → should be detected
        assert!(
            low_diffs.is_empty(),
            "Body hash drift should NOT be reported at low sensitivity"
        );
        // But the endpoint is same, ports are same, status is same
        // So only body hash differs
        assert!(
            med_diffs.iter().any(|d| d.contains("Response body signature")),
            "Body hash drift should be detected at medium sensitivity"
        );
    }

    #[test]
    fn test_header_drift_only_at_high() {
        let current = modified_headers_state();
        let baseline = sample_state();

        // Status=200, body hash="abc" match, only headers differ
        let low_diffs = detect_drift(&current, &baseline, "low");
        let med_diffs = detect_drift(&current, &baseline, "medium");
        let high_diffs = detect_drift(&current, &baseline, "high");

        assert!(low_diffs.is_empty(), "Header drift not at low");
        assert!(med_diffs.is_empty(), "Header drift not at medium");
        assert!(
            high_diffs.iter().any(|d| d.contains("header structure")),
            "Header structure drift should be detected at high sensitivity"
        );
    }

    #[test]
    fn test_new_endpoint_detected() {
        let current = added_endpoint_state();
        let baseline = sample_state();
        let diffs = detect_drift(&current, &baseline, "low");
        assert!(
            diffs.iter().any(|d| d.contains("New endpoints")),
            "New endpoints should be reported"
        );
    }

    #[test]
    fn test_new_port_detected() {
        let current = added_port_state();
        let baseline = sample_state();
        let diffs = detect_drift(&current, &baseline, "low");
        assert!(
            diffs.iter().any(|d| d.contains("New open ports")),
            "New ports should be reported"
        );
    }
}