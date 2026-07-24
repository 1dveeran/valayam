// TODO: Implement OAuth/OIDC Audit (Phase 16).
// - Flow exploitation for CSRF, open redirects, and implicit token leakage.
// - JWT algorithm confusion (e.g., 'none' algorithm) and weak HMAC cracking.
// - Probe for misconfigured redirect_uri validation.

pub mod executor;


use valayam_engine::impl_scan_plugin;
use valayam_engine::traits::PluginOutcome;
use valayam_network::network::http::StealthHttpClient;
use std::sync::Arc;

impl_scan_plugin!(OauthAuditPlugin, "oauth_audit", oauth_audit,
    state: { client: Arc<StealthHttpClient> },
    |self, ctx, template, finding_tx| {
        if let Some(res) = executor::execute(
            &ctx.target, &self.client, &template.oauth_audit,
            &template.id, &template.info,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);
