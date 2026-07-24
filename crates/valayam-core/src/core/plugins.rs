//! All scan plugin adapters, generated via `impl_scan_plugin!` macro.
//!
//! Each plugin wraps an existing feature executor behind the ScanPlugin trait.

use valayam_engine::impl_scan_plugin;
use valayam_engine::traits::PluginOutcome;
use valayam_models::TemplateMetadata;
use valayam_network::network::http::StealthHttpClient;
use std::sync::Arc;

// ─── Core Protocol Plugins ────────────────────────────────────────────────

impl_scan_plugin!(
    HttpScanPlugin, "http_scan", requests,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        let mut vars = ctx.snapshot_variables().await;
        let results = crate::features::http_scan::executor::execute(
            &self.client, &ctx.target, &template.requests,
            &template.id, &template.info as &dyn TemplateMetadata, &mut vars,
        ).await;
        {
            let mut scope = ctx.variables.write().await;
            for (k, v) in &vars {
                scope.set("http_scan", k.clone(), v.clone());
            }
        }
        if !results.is_empty() {
            let count = results.len();
            for res in results {
                let _ = finding_tx.send(res).await;
            }
            PluginOutcome::Matched { count }
        } else {
            PluginOutcome::NoMatch
        }
    }
);

impl_scan_plugin!(
    NetworkScanPlugin, "network_scan", network,
    |ctx, template, finding_tx| {
        let target_host = &ctx.target_host;
        let results = crate::features::network_scan::executor::execute(
            &ctx.target, target_host, &template.network,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await;
        if !results.is_empty() {
            let count = results.len();
            for res in results {
                let _ = finding_tx.send(res).await;
            }
            PluginOutcome::Matched { count }
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
            &template.dns, &template.id, &template.info as &dyn TemplateMetadata, &vars,
        ).await;
        if let Some(res) = result {
            let _ = finding_tx.send(res).await;
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
        let results = crate::features::tls_audit::executor::execute(
            &template.tls, &template.id, &template.info as &dyn TemplateMetadata, &vars,
        ).await;
        if !results.is_empty() {
            let count = results.len();
            for res in results {
                let _ = finding_tx.send(res).await;
            }
            PluginOutcome::Matched { count }
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
            &template.id, &template.info as &dyn TemplateMetadata, &vars,
        ).await;
        if let Some(res) = result {
            let _ = finding_tx.send(res).await;
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
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await;
        if let Some(res) = result {
            let _ = finding_tx.send(res).await;
            PluginOutcome::Matched { count: 1 }
        } else {
            PluginOutcome::NoMatch
        }
    }
);

// ─── Extended Feature Plugins ─────────────────────────────────────────────

impl_scan_plugin!(CloudSecPlugin, "cloud_sec", cloud,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        for cloud_t in &template.cloud {
            if let Some(res) = crate::features::cloud_sec::executor::execute_cloud_probe(
                &self.client, &ctx.target, cloud_t,
            ).await {
                let _ = finding_tx.send(res).await;
                return PluginOutcome::Matched { count: 1 };
            }
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(AuthLogicPlugin, "auth_logic", logic,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(auth) = &template.auth {
            let vars = ctx.snapshot_variables().await;
            if let Some(res) = crate::features::auth_logic::executor::execute(
                &self.client, &ctx.target, &template.logic, auth,
                &template.id, &template.info as &dyn TemplateMetadata, &vars,
            ).await {
                let _ = finding_tx.send(res).await;
                return PluginOutcome::Matched { count: 1 };
            }
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(DeepAnalysisPlugin, "deep_analysis", deep_analysis,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::deep_analysis::executor::execute(
            &self.client, &ctx.target, &template.deep_analysis,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);


impl_scan_plugin!(SbomAuditPlugin, "sbom_audit", sbom_audit,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::sbom_audit::executor::execute(
            &ctx.target, &self.client, &template.sbom_audit,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(GrpcAuditPlugin, "grpc_audit", grpc_audit,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::grpc_audit::executor::execute(
            &ctx.target, &self.client, &template.grpc_audit,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);


impl_scan_plugin!(DriftDetectPlugin, "drift_detect", drift_detect,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::drift_detect::executor::execute(
            &ctx.target, &self.client, &template.drift_detect,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(CredMonitorPlugin, "cred_monitor", cred_monitor,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::cred_monitor::executor::execute(
            &ctx.target, &self.client, &template.cred_monitor,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);


impl_scan_plugin!(IdpAuditPlugin, "idp_audit", idp_audit,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::idp_audit::executor::execute(
            &template.idp_audit, &template.id, &template.info as &dyn TemplateMetadata,
            &self.client, &ctx.target,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(AwsEscalatePlugin, "aws_escalate", aws_escalate,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::aws_escalate::executor::execute(
            &ctx.target, &self.client, &template.aws_escalate,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(AzureGcpEscalatePlugin, "azure_gcp_escalate", azure_gcp_escalate,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::azure_gcp_escalate::executor::execute(
            &ctx.target, &self.client, &template.azure_gcp_escalate,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(BrowserAuditPlugin, "browser_audit", browser_audit,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::browser_audit::executor::execute(
            &ctx.target, &self.client, &template.browser_audit,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);


impl_scan_plugin!(ScadaAuditPlugin, "scada_audit", scada_audit,
    |ctx, template, finding_tx| {
        if let Some(res) = crate::features::scada_audit::executor::execute(
            &ctx.target, &template.scada_audit, &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(AutoRedteamPlugin, "auto_redteam", auto_redteam,
    |ctx, template, finding_tx| {
        if let Some(res) = crate::features::auto_redteam::executor::execute(
            &template.auto_redteam, &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(ImplantDeployPlugin, "implant_deploy", implant_deploy,
    |ctx, template, finding_tx| {
        if let Some(res) = crate::features::implant_deploy::executor::execute(
            &template.implant_deploy, &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(ClientSecretAuditPlugin, "client_secret_audit", client_secret_audit,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::client_secret_audit::executor::execute(
            &ctx.target, &self.client, &template.client_secret_audit,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(DomRedirectAuditPlugin, "dom_redirect_audit", dom_redirect_audit,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::dom_redirect_audit::executor::execute(
            &ctx.target, &self.client, &template.dom_redirect_audit,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(CorsAuditPlugin, "cors_audit", cors_audit,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::cors_audit::executor::execute(
            &ctx.target, &self.client, &template.cors_audit,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(CspAuditPlugin, "csp_audit", csp_audit,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::csp_audit::executor::execute(
            &ctx.target, &self.client, &template.csp_audit,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(WafBypassVerifyPlugin, "waf_bypass_verify", waf_bypass_verify,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::waf_bypass_verify::executor::execute(
            &ctx.target_host, &self.client, &template.waf_bypass_verify,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(HeaderScorecardPlugin, "header_scorecard", header_scorecard,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::header_scorecard::executor::execute(
            &ctx.target, &self.client, &template.header_scorecard,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(ReputationAuditPlugin, "reputation_audit", reputation_audit,
    |ctx, template, finding_tx| {
        if let Some(res) = crate::features::reputation_audit::executor::execute(
            &template.reputation_audit, &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(CtLogAuditPlugin, "ct_log_audit", ct_log_audit,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::ct_log_audit::executor::execute(
            &template.ct_log_audit, &template.id, &template.info as &dyn TemplateMetadata, &self.client,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

// We won't add MitreMapping/RemediationGen here because those operate on results (post-processing).
// In the current orchestrator layout, they might just be ignored or handled later.
// The old loader.rs ignored the return values for those since they modified results in-place without complex ownership.
// But we'll provide dummy plugins just so they compile if someone wants to wire them up.

impl_scan_plugin!(RemediationGenPlugin, "remediation_gen", remediation_gen,
    |ctx, _template, _finding_tx| {
        // Post processing isn't fully wired in parallel execution context yet
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(MitreMappingPlugin, "mitre_mapping", mitre_mapping,
    |ctx, _template, _finding_tx| {
        // Post processing isn't fully wired in parallel execution context yet
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(ContainerAuditPlugin, "container_audit", container_audit,
    |ctx, template, finding_tx| {
        if let Some(res) = crate::features::container_audit::executor::execute(
            &template.container_audit, &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(K8sAuditPlugin, "k8s_audit", k8s_audit,
    |ctx, template, finding_tx| {
        if let Some(res) = crate::features::k8s_audit::executor::execute(
            &template.k8s_audit, &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(SastTaintPlugin, "sast_taint", sast_taint,
    |ctx, template, finding_tx| {
        if let Some(res) = crate::features::sast_taint::executor::execute(
            &template.sast_taint, &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(SastSecretsPlugin, "sast_secrets", sast_secrets,
    |ctx, template, finding_tx| {
        if let Some(res) = crate::features::sast_secrets::executor::execute(
            &template.sast_secrets, &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(SubdomainTakeoverPlugin, "subdomain_takeover", subdomain_takeover,
    |ctx, template, finding_tx| {
        if let Some(res) = crate::features::subdomain_takeover::executor::execute(
            &ctx.target_host, &template.subdomain_takeover,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(PortScanPlugin, "port_scan", port_scan,
    |ctx, template, finding_tx| {
        if let Some(res) = crate::features::port_scan::executor::execute(
            &ctx.target_host, &template.port_scan,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(SchemaDriftPlugin, "schema_drift", schema_drift,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::schema_drift::executor::execute(
            &ctx.target, &self.client, &template.schema_drift,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(PiiLeakAuditPlugin, "pii_leak_audit", pii_leak_audit,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = crate::features::pii_leak_audit::executor::execute(
            &ctx.target, &self.client, &template.pii_leak_audit,
            &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

impl_scan_plugin!(CicdAuditPlugin, "cicd_audit", cicd_audit,
    |ctx, template, finding_tx| {
        if let Some(res) = crate::features::cicd_audit::executor::execute(
            &template.cicd_audit, &template.id, &template.info as &dyn TemplateMetadata,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);


#[cfg(test)]
mod tests {
    use super::*;
    use valayam_engine::traits::ScanPlugin;
    use valayam_models::templates::schema::VulnerabilityTemplate;

    fn empty_template() -> VulnerabilityTemplate {
        VulnerabilityTemplate::default()
    }

    #[test]
    fn test_http_scan_plugin_new_and_name() {
        let client = Arc::new(crate::network::http::StealthHttpClient::new(false, false, None, false).unwrap());
        let plugin = HttpScanPlugin::new(client);
        assert_eq!(plugin.name(), "http_scan");
    }

    #[test]
    fn test_http_scan_applicable_empty() {
        let client = Arc::new(crate::network::http::StealthHttpClient::new(false, false, None, false).unwrap());
        let plugin = HttpScanPlugin::new(client);
        // Empty template — requests field is empty, so not applicable
        assert!(!plugin.is_applicable(&empty_template()));
    }

    #[test]
    fn test_network_scan_plugin_new() {
        let plugin = NetworkScanPlugin::new();
        assert_eq!(plugin.name(), "network_scan");
        assert!(!plugin.is_applicable(&empty_template()));
    }

    #[test]
    fn test_dns_audit_plugin_new() {
        let plugin = DnsAuditPlugin::new();
        assert_eq!(plugin.name(), "dns_audit");
        assert!(!plugin.is_applicable(&empty_template()));
    }

    #[test]
    fn test_tls_audit_plugin_new() {
        let plugin = TlsAuditPlugin::new();
        assert_eq!(plugin.name(), "tls_audit");
        assert!(!plugin.is_applicable(&empty_template()));
    }

    #[test]
    fn test_scripting_plugin_new() {
        let plugin = ScriptingPlugin::new();
        assert_eq!(plugin.name(), "scripting");
        assert!(!plugin.is_applicable(&empty_template()));
    }

    #[test]
    fn test_fuzzer_plugin_new() {
        let client = Arc::new(crate::network::http::StealthHttpClient::new(false, false, None, false).unwrap());
        let plugin = FuzzerPlugin::new(client);
        assert_eq!(plugin.name(), "fuzzer");
        assert!(!plugin.is_applicable(&empty_template()));
    }

    #[test]
    fn test_plugin_api_version() {
        let plugin = HttpScanPlugin::new(Arc::new(crate::network::http::StealthHttpClient::new(false, false, None, false).unwrap()));
        assert_eq!(plugin.api_version(), "1.0");
    }

    #[test]
    fn test_plugin_timeout_default() {
        let plugin = HttpScanPlugin::new(Arc::new(crate::network::http::StealthHttpClient::new(false, false, None, false).unwrap()));
        assert_eq!(plugin.timeout(), std::time::Duration::from_secs(60));
    }

    #[test]
    fn test_plugin_depends_on_default_is_empty() {
        let plugin = NetworkScanPlugin::new();
        assert!(plugin.depends_on().is_empty());
    }
}
