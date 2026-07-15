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
