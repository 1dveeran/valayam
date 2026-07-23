// TODO: Implement Hardware & IoT Protocol Security (Phase 19).
// - MQTT broker probing and wildcard (`#`) topic subscription.
// - CoAP payload fuzzing to trigger DoS or RCE.
// - Identify default credentials on common IoT administration interfaces.

pub mod executor;


use valayam_engine::impl_scan_plugin;
use valayam_engine::traits::PluginOutcome;

impl_scan_plugin!(IotAuditPlugin, "iot_audit", iot_audit,
    |ctx, template, finding_tx| {
        if let Some(res) = executor::execute(
            &template.iot_audit, &template.id, &template.info,
        ).await {
            let _ = finding_tx.send(valayam_models::finding::FindingOwned {
                template_id: res.template_id.clone(),
                template_name: res.template_name.clone(),
                severity: res.template_severity.clone(),
                target: res.target.clone(),
                matched_at: res.payload.clone(),
                description: res.solution.clone(),
                solution: None,
                extracted_data: None,
                metadata: res.compliance.clone(),
            }).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);
