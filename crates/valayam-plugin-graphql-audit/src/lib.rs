// TODO: Implement GraphQL Introspection & Fuzzing (Phase 14).
// - Schema dumping and nested query generation via introspection.
// - Depth-limiting and batching vulnerability checks.
// - Enumerate hidden mutations and exposed administrative queries.

pub mod executor;
pub mod mutator;


use valayam_engine::impl_scan_plugin;
use valayam_engine::traits::PluginOutcome;
use valayam_network::network::http::StealthHttpClient;
use std::sync::Arc;

impl_scan_plugin!(GraphqlAuditPlugin, "graphql_audit", graphql_audit,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = executor::execute(
            &ctx.target, &self.client, &template.graphql_audit,
            &template.id, &template.info,
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
