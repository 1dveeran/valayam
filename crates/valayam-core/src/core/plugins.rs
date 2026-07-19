//! All scan plugin adapters, generated via `impl_scan_plugin!` macro.
//!
//! Each plugin wraps an existing feature executor behind the ScanPlugin trait.
//! Adding a new plugin = ~10 lines here + one `registry.register()` call.

use crate::core::traits::PluginOutcome;
use crate::core::scan_result_bridge::scan_result_to_finding;
use crate::network::http::StealthHttpClient;
use crate::impl_scan_plugin;
use std::sync::Arc;

// ─── Core Protocol Plugins (stateful — need HTTP client) ────────────────

impl_scan_plugin!(
    HttpScanPlugin, "http_scan", requests,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        let mut vars = ctx.snapshot_variables().await;
        let result = crate::features::http_scan::executor::execute(
            &self.client, &ctx.target, &template.requests,
            &template.id, &template.info, &mut vars,
        ).await;
        // Write back any variables extracted during HTTP phase
        {
            let mut scope = ctx.variables.write().await;
            for (k, v) in &vars {
                scope.set("http_scan", k.clone(), v.clone());
            }
        }
        if let Some(res) = result {
            let _ = finding_tx.send(scan_result_to_finding(res)).await;
            PluginOutcome::Matched { count: 1 }
        } else {
            PluginOutcome::NoMatch
        }
    }
);

impl_scan_plugin!(
    NetworkScanPlugin, "network_scan", network,
    |ctx, template, finding_tx| {
        let target_host = &ctx.target_host;
        let result = crate::features::network_scan::executor::execute(
            &ctx.target, target_host, &template.network,
            &template.id, &template.info,
        ).await;
        if let Some(res) = result {
            let _ = finding_tx.send(scan_result_to_finding(res)).await;
            PluginOutcome::Matched { count: 1 }
        } else {
            PluginOutcome::NoMatch
        }
    }
);

impl_scan_plugin!(
    DnsAuditPlugin, "dns_audit", dns,
    |ctx, template, finding_tx| {
        let vars = ctx.snapshot_variables().await;
        let result = crate::features::dns_audit::executor::execute(
            &template.dns, &template.id, &template.info, &vars,
        ).await;
        if let Some(res) = result {
            let _ = finding_tx.send(scan_result_to_finding(res)).await;
            PluginOutcome::Matched { count: 1 }
        } else {
            PluginOutcome::NoMatch
        }
    }
);

impl_scan_plugin!(
    TlsAuditPlugin, "tls_audit", tls,
    |ctx, template, finding_tx| {
        let vars = ctx.snapshot_variables().await;
        let result = crate::features::tls_audit::executor::execute(
            &template.tls, &template.id, &template.info, &vars,
        ).await;
        if let Some(res) = result {
            let _ = finding_tx.send(scan_result_to_finding(res)).await;
            PluginOutcome::Matched { count: 1 }
        } else {
            PluginOutcome::NoMatch
        }
    }
);

impl_scan_plugin!(
    ScriptingPlugin, "scripting", scripts,
    |ctx, template, finding_tx| {
        let vars = ctx.snapshot_variables().await;
        let result = crate::features::scripting::executor::execute(
            &ctx.target, &ctx.target_host, &template.scripts,
            &template.id, &template.info, &vars,
        ).await;
        if let Some(res) = result {
            let _ = finding_tx.send(scan_result_to_finding(res)).await;
            PluginOutcome::Matched { count: 1 }
        } else {
            PluginOutcome::NoMatch
        }
    }
);

impl_scan_plugin!(
    FuzzerPlugin, "fuzzer", fuzz,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        let result = crate::features::fuzzer::executor::execute(
            &self.client, &ctx.target, &template.fuzz,
            &template.id, &template.info,
        ).await;
        if let Some(res) = result {
            let _ = finding_tx.send(scan_result_to_finding(res)).await;
            PluginOutcome::Matched { count: 1 }
        } else {
            PluginOutcome::NoMatch
        }
    }
);

// ─── Extended Feature Plugins (stateless unless noted) ──────────────────

impl_scan_plugin!(CloudSecPlugin, "cloud_sec", cloud,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        for cloud_t in &template.cloud {
            if let Some(res) = crate::features::cloud_sec::executor::execute_cloud_probe(
                &self.client, &ctx.target, cloud_t,
            ).await {
                let _ = finding_tx.send(scan_result_to_finding(res)).await;
                return PluginOutcome::Matched { count: 1 };
            }
        }
        PluginOutcome::NoMatch
    }
);

// We add dummy implementations for all the other ones for now,
// or we assume they will be filled out similarly as they are added to `features/*`
