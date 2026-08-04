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
        template.has_section("http-request")
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
            // [STUB] Synergistic Execution: Hand-off to Wasm Plugin for Deep Analysis and it should be given as a option so that all the results are not shared with wasm plugin for deep analysis as the wasm plugin must support the deep analysis
            if !template.deep_analysis.is_empty() {
                tracing::info!(
                    "Synergistic Execution (Stub): Passing {} finding(s) to Wasm Plugin for Deep Analysis ({} rules)",
                    results.len(),
                    template.deep_analysis.len()
                );
            }

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
        template.has_section("schema-drift")
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
        template.has_section("dns")
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
        template.has_section("port-scan")
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
    pub server: Arc<valayam_oob::server::OobServer>,
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
    use valayam_models::templates::schema::VulnerabilityTemplate;

    fn empty_template() -> VulnerabilityTemplate {
        VulnerabilityTemplate {
            id: "test".to_string(),
            info: valayam_models::templates::schema::TemplateInfo {
                name: "Test".to_string(),
                severity: "Info".to_string(),
                author: None,
                description: None,
                tags: vec![],
                compliance: Default::default(),
            },
            ..VulnerabilityTemplate::empty()
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
