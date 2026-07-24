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
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);
