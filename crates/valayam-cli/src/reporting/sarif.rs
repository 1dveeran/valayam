use valayam_core::core::result::ScanResult;
use serde_json::json;

pub fn generate_sarif(results: &[ScanResult]) -> serde_json::Value {
    let mut runs = vec![];
    let mut results_sarif = vec![];

    for r in results {
        results_sarif.push(json!({
            "ruleId": r.template_id,
            "level": "warning", // Map actual severity
            "message": { "text": r.template_name },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": r.target
                        }
                    }
                }
            ]
        }));
    }

    runs.push(json!({
        "tool": {
            "driver": {
                "name": "Valayam",
                "version": "0.1.0",
                "informationUri": "https://github.com/valayam"
            }
        },
        "results": results_sarif
    }));

    json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use valayam_core::core::result::ScanResult;

    fn sample_results() -> Vec<ScanResult> {
        vec![
            ScanResult {
                template_id: "test-001".into(),
                template_name: "SQLi Test".into(),
                template_severity: "high".into(),
                target: "https://example.com/login".into(),
                payload: "detected".into(),
                ..Default::default()
            },
        ]
    }

    #[test]
    fn test_sarif_has_correct_schema() {
        let sarif = generate_sarif(&sample_results());
        assert_eq!(sarif["$schema"], "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json");
        assert_eq!(sarif["version"], "2.1.0");
    }

    #[test]
    fn test_sarif_contains_result() {
        let sarif = generate_sarif(&sample_results());
        let runs = sarif["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        let results = runs[0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "test-001");
        assert_eq!(results[0]["message"]["text"], "SQLi Test");
    }

    #[test]
    fn test_sarif_target_in_locations() {
        let sarif = generate_sarif(&sample_results());
        let location = &sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(location["uri"], "https://example.com/login");
    }

    #[test]
    fn test_sarif_empty_results() {
        let sarif = generate_sarif(&[]);
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_sarif_multiple_results() {
        let results = vec![
            ScanResult { template_id: "a".into(), template_name: "A".into(), ..Default::default() },
            ScanResult { template_id: "b".into(), template_name: "B".into(), ..Default::default() },
        ];
        let sarif = generate_sarif(&results);
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_sarif_tool_info() {
        let sarif = generate_sarif(&sample_results());
        let driver = &sarif["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "Valayam");
        assert_eq!(driver["version"], "0.1.0");
    }
}
