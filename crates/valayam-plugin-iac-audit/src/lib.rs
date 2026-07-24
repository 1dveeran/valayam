#![allow(dead_code)]
// TODO: Implement IaC Scanning (Phase 13).
// - Static analysis for Terraform, K8s YAML, and Dockerfiles.
// - Misconfiguration matchers (e.g. privileged containers, exposed secrets).
// - Map discovered IaC vulnerabilities directly to compliance frameworks.

pub mod executor;


use valayam_engine::impl_scan_plugin;
use valayam_engine::traits::PluginOutcome;

impl_scan_plugin!(IacAuditPlugin, "iac_audit", iac_audit,
    |ctx, template, finding_tx| {
        if let Some(res) = executor::execute(
            &template.iac_audit, &template.id, &template.info,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);
