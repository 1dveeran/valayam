use crate::features::schema_drift;
use crate::network::http::StealthHttpClient;
use async_trait::async_trait;
use std::sync::Arc;
use valayam_engine::traits::ScanContext;
use valayam_engine::traits::{PluginOutcome, ScanPlugin};
use valayam_models::templates::schema::{TemplateMetadata, VulnerabilityTemplate};

// ─── Native Plugins ─────────────────────────────────────────────────────────────

pub struct HttpScanPlugin {
    client: Arc<StealthHttpClient>,
}

impl HttpScanPlugin {
    pub fn new(client: Arc<StealthHttpClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ScanPlugin for HttpScanPlugin {
    fn name(&self) -> &str {
        "http_scan"
    }

    fn is_applicable(&self, template: &VulnerabilityTemplate) -> bool {
        !template.requests.is_empty()
    }

    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        let mut vars = ctx.snapshot_variables().await;
        let template = ctx.template.clone();
        let results = crate::features::http_scan::executor::execute(
            &self.client,
            &ctx.target,
            &template.requests,
            &template.id,
            &template.info as &dyn TemplateMetadata,
            &mut vars,
        )
        .await;

        if !results.is_empty() {
            for res in results {
                let _ = ctx.finding_tx.send(res).await;
            }
            PluginOutcome::Matched { count: 1 }
        } else {
            PluginOutcome::NoMatch
        }
    }
}

pub struct SchemaDriftPlugin {
    client: Arc<StealthHttpClient>,
}

impl SchemaDriftPlugin {
    pub fn new(client: Arc<StealthHttpClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ScanPlugin for SchemaDriftPlugin {
    fn name(&self) -> &str {
        "schema_drift"
    }

    fn is_applicable(&self, template: &VulnerabilityTemplate) -> bool {
        !template.schema_drift.is_empty()
    }

    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        if let Some(res) = schema_drift::executor::execute(
            &ctx.target,
            &self.client,
            &ctx.template.schema_drift,
            &ctx.template.id,
            &ctx.template.info as &dyn TemplateMetadata,
        )
        .await
        {
            let _ = ctx.finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
}

pub struct DnsAuditPlugin;
#[async_trait]
impl ScanPlugin for DnsAuditPlugin {
    fn name(&self) -> &str {
        "dns_audit"
    }
    fn is_applicable(&self, template: &VulnerabilityTemplate) -> bool {
        !template.dns.is_empty()
    }
    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        let vars = ctx.snapshot_variables().await;
        let findings = valayam_core_net::features::dns_audit::executor::execute(
            &ctx.template.dns,
            &ctx.template.id,
            &ctx.template.info as &dyn TemplateMetadata,
            &vars,
        )
        .await;
        let count = findings.len();
        for f in findings {
            let _ = ctx.finding_tx.send(f).await;
        }
        if count > 0 {
            PluginOutcome::Matched { count }
        } else {
            PluginOutcome::NoMatch
        }
    }
}

pub struct PortScanPlugin;
#[async_trait]
impl ScanPlugin for PortScanPlugin {
    fn name(&self) -> &str {
        "port_scan"
    }
    fn is_applicable(&self, template: &VulnerabilityTemplate) -> bool {
        !template.port_scan.is_empty()
    }
    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        if let Some(finding) = valayam_core_net::features::port_scan::executor::execute(
            &ctx.target,
            &ctx.template.port_scan,
            &ctx.template.id,
            &ctx.template.info as &dyn TemplateMetadata,
        )
        .await
        {
            let _ = ctx.finding_tx.send(finding).await;
            PluginOutcome::Matched { count: 1 }
        } else {
            PluginOutcome::NoMatch
        }
    }
}

pub struct ThreatIntelPlugin {
    pub matcher: Arc<crate::features::threat_intel::ioc_matcher::IocMatcher>,
}
#[async_trait]
impl ScanPlugin for ThreatIntelPlugin {
    fn name(&self) -> &str {
        "threat_intel"
    }
    fn is_applicable(&self, _template: &VulnerabilityTemplate) -> bool {
        // Run threat intel on targets if the template has indicators (for now, run if domain matches)
        false // Requires more complex integration with active findings
    }
    async fn execute(&self, _ctx: &ScanContext) -> PluginOutcome {
        PluginOutcome::NoMatch
    }
}

pub struct OobPlugin {
    pub server: Arc<valayam_core_net::features::oob::server::OobServer>,
}
#[async_trait]
impl ScanPlugin for OobPlugin {
    fn name(&self) -> &str {
        "oob"
    }
    fn is_applicable(&self, template: &VulnerabilityTemplate) -> bool {
        template.oob_interaction
    }
    async fn execute(&self, _ctx: &ScanContext) -> PluginOutcome {
        // In a real scan, OOB polling happens continuously or after requests.
        // We defer full execution logic to the orchestrator for OOB correlation.
        PluginOutcome::NoMatch
    }
}

pub struct ShellsPlugin;
#[async_trait]
impl ScanPlugin for ShellsPlugin {
    fn name(&self) -> &str {
        "shells"
    }
    fn is_applicable(&self, _template: &VulnerabilityTemplate) -> bool {
        false // Usually triggered manually or by specific exploits
    }
    async fn execute(&self, _ctx: &ScanContext) -> PluginOutcome {
        PluginOutcome::NoMatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use valayam_models::templates::schema::{TemplateInfo, VulnerabilityTemplate};

    fn empty_template() -> VulnerabilityTemplate {
        VulnerabilityTemplate {
            id: "test".to_string(),
            info: TemplateInfo {
                name: "Test".to_string(),
                severity: "Info".to_string(),
                description: None,
                compliance: Default::default(),
            },
            auth: None,
            requests: vec![],
            network: vec![],
            scripts: vec![],
            dns: vec![],
            tls: vec![],
            fuzz: vec![],
            cloud: vec![],
            logic: vec![],
            deep_analysis: vec![],
            iac_audit: vec![],
            sbom_audit: vec![],
            grpc_audit: vec![],
            graphql_audit: vec![],
            drift_detect: vec![],
            cred_monitor: vec![],
            oauth_audit: vec![],
            idp_audit: vec![],
            aws_escalate: vec![],
            azure_gcp_escalate: vec![],
            browser_audit: vec![],
            iot_audit: vec![],
            scada_audit: vec![],
            auto_redteam: vec![],
            implant_deploy: vec![],
            client_secret_audit: vec![],
            dom_redirect_audit: vec![],
            cors_audit: vec![],
            csp_audit: vec![],
            waf_bypass_verify: vec![],
            header_scorecard: vec![],
            reputation_audit: vec![],
            ct_log_audit: vec![],
            remediation_gen: vec![],
            mitre_mapping: vec![],
            container_audit: vec![],
            k8s_audit: vec![],
            sast_taint: vec![],
            sast_secrets: vec![],
            subdomain_takeover: vec![],
            port_scan: vec![],
            schema_drift: vec![],
            pii_leak_audit: vec![],
            cicd_audit: vec![],
            dependency_audit: vec![],
            easm: vec![],
            web3_audit: vec![],
            mobile_audit: vec![],
            serverless_audit: vec![],
            auto_exploit: vec![],
            ui_proxy: vec![],
            oob_interaction: false,
        }
    }

    #[test]
    fn test_http_scan_plugin_new_and_name() {
        let client = Arc::new(
            crate::network::http::StealthHttpClient::new(false, false, None, false).unwrap(),
        );
        let plugin = HttpScanPlugin::new(client);
        assert_eq!(plugin.name(), "http_scan");
    }

    #[test]
    fn test_http_scan_applicable_empty() {
        let client = Arc::new(
            crate::network::http::StealthHttpClient::new(false, false, None, false).unwrap(),
        );
        let plugin = HttpScanPlugin::new(client);
        assert!(!plugin.is_applicable(&empty_template()));
    }
}
