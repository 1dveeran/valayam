// TODO: Optimize Template Orchestration Pipeline.
// - Ensure `{{variable}}` context flows thread-safely between phases.
// - Add telemetry spans for performance monitoring of each execution slice.
use valayam_engine::rate_limiter::RateLimiter;
use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use valayam_engine::variables::build_initial_context;
use crate::features::{dns_audit, http_scan, network_scan, scripting, tls_audit, fuzzer, easm};
use crate::network::http::StealthHttpClient;
use super::schema::VulnerabilityTemplate;
use url::Url;

/// Orchestrates the execution of a single template against a target.
///
/// Executes feature slices in order: HTTP → Network → DNS → TLS → Scripts.
/// A shared `HashMap<String, String>` variable context flows through all phases.
/// Extractors from the HTTP phase populate the context for subsequent phases.
///
/// # Arguments
/// * `client` — The shared stealth HTTP client.
/// * `target_url` — The target URL to scan.
/// * `template` — The parsed template to execute.
/// * `rate_limiter` — Optional global rate limiter.
#[tracing::instrument(skip(client, template, rate_limiter), fields(target = %target_url, template = %template.id))]
pub async fn execute_template_inner(
    client: &StealthHttpClient,
    target_url: &str,
    template: &VulnerabilityTemplate,
    rate_limiter: Option<&RateLimiter>,
) -> Option<FindingOwned> {
    // Derive the bare hostname once for slices that need it
    let target_host = Url::parse(target_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| target_url.to_string());

    // Build the shared variable context seeded with built-in variables
    let mut variables = build_initial_context(target_url, &target_host);

    // Phase 0: External Attack Surface Management (EASM)
    if !template.easm.is_empty() {
        if let Some(result) = easm::executor::execute(
            client.inner(),
            target_url,
            &target_host,
            &template.easm,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            // Usually we'd branch out the target here. 
            // For now, we return the subdomains found.
            return Some(result);
        }
    }

    // Phase 1: HTTP Requests (with extractors & helpers)
    if !template.requests.is_empty() {
        if let Some(rl) = rate_limiter {
            rl.acquire().await;
        }

        let results = http_scan::executor::execute(
            client,
            target_url,
            &template.requests,
            &template.id,
            &template.info as &dyn TemplateMetadata,
            &mut variables,
        )
        .await;
        if !results.is_empty() {
            return Some(results.into_iter().next().unwrap());
        }
    }

    // Phase 2: Network Scanning (TCP with banner grabbing)
    if !template.network.is_empty() {
        let results = network_scan::executor::execute(
            target_url,
            &target_host,
            &template.network,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await;
        if !results.is_empty() {
            return Some(results.into_iter().next().unwrap());
        }
    }

    // Phase 3: DNS Auditing
    if !template.dns.is_empty() {
        if let Some(result) = dns_audit::executor::execute(
            &template.dns,
            &template.id,
            &template.info as &dyn TemplateMetadata,
            &variables,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 4: TLS Certificate Auditing
    if !template.tls.is_empty() {
        let results = tls_audit::executor::execute(
            &template.tls,
            &template.id,
            &template.info as &dyn TemplateMetadata,
            &variables,
        )
        .await;
        if !results.is_empty() {
            return Some(results.into_iter().next().unwrap());
        }
    }

    // Phase 5: Script Execution (Rhai)
    if !template.scripts.is_empty() {
        if let Some(result) = scripting::executor::execute(
            target_url,
            &target_host,
            &template.scripts,
            &template.id,
            &template.info as &dyn TemplateMetadata,
            &variables,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 5: Fuzzing Engine
    if !template.fuzz.is_empty() {
        if let Some(result) = fuzzer::executor::execute(
            client,
            target_url,
            &template.fuzz,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 6: Cloud Probing
    if !template.cloud.is_empty() {
        for cloud_t in &template.cloud {
            if let Some(result) = crate::features::cloud_sec::executor::execute_cloud_probe(
                client,
                target_url,
                cloud_t,
            )
            .await
            {
                return Some(result);
            }
        }
    }

    // Phase 7: Stateful Logic & Authorization Testing (IDOR)
    if !template.logic.is_empty() {
        if let Some(auth) = &template.auth {
            if let Some(result) = crate::features::auth_logic::executor::execute(
                client,
                target_url,
                &template.logic,
                auth,
                &template.id,
                &template.info as &dyn TemplateMetadata,
                &variables,
            )
            .await
            {
                return Some(result);
            }
        }
    }

    // Phase 8: Deep Analysis & Evasion
    if !template.deep_analysis.is_empty() {
        if let Some(result) = crate::features::deep_analysis::executor::execute(
            client,
            target_url,
            &template.deep_analysis,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 9: IaC & SBOM Audit
    if !template.sbom_audit.is_empty() {
        if let Some(result) = crate::features::sbom_audit::executor::execute(
            target_url,
            client,
            &template.sbom_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 10: gRPC & GraphQL Audit
    if !template.grpc_audit.is_empty() {
        if let Some(result) = crate::features::grpc_audit::executor::execute(
            target_url,
            client,
            &template.grpc_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 11: Drift Detect & Cred Monitor
    if !template.drift_detect.is_empty() {
        if let Some(result) = crate::features::drift_detect::executor::execute(
            target_url,
            client,
            &template.drift_detect,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }
    if !template.cred_monitor.is_empty() {
        if let Some(result) = crate::features::cred_monitor::executor::execute(
            target_url,
            client,
            &template.cred_monitor,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }
    if !template.container_audit.is_empty() {
        if let Some(result) = crate::features::container_audit::executor::execute(
            &template.container_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }
    if !template.cicd_audit.is_empty() {
        if let Some(result) = crate::features::cicd_audit::executor::execute(
            &template.cicd_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 12: Zero-Trust & Identity Security
    if !template.idp_audit.is_empty() {
        if let Some(result) = crate::features::idp_audit::executor::execute(
            &template.idp_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
            client,
            target_url,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 13: Multi-Cloud Post-Exploitation
    if !template.aws_escalate.is_empty() {
        if let Some(result) = crate::features::aws_escalate::executor::execute(
            target_url,
            client,
            &template.aws_escalate,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }
    if !template.azure_gcp_escalate.is_empty() {
        if let Some(result) = crate::features::azure_gcp_escalate::executor::execute(
            target_url,
            client,
            &template.azure_gcp_escalate,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 21: Client-Side Security Auditing

    // Phase 14: Browser Exploitation
    if !template.browser_audit.is_empty() {
        if let Some(result) = crate::features::browser_audit::executor::execute(
            target_url,
            client,
            &template.browser_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 15: Hardware & IoT Protocol Security
    if !template.scada_audit.is_empty() {
        if let Some(result) = crate::features::scada_audit::executor::execute(
            target_url,
            &template.scada_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 20: Autonomous Red Teaming & Auto-Exploitation
    if !template.auto_redteam.is_empty() {
        if let Some(result) = crate::features::auto_redteam::executor::execute(
            &template.auto_redteam,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }
    if !template.implant_deploy.is_empty() {
        if let Some(result) = crate::features::implant_deploy::executor::execute(
            &template.implant_deploy,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 21: Client-Side Security Auditing
    if !template.client_secret_audit.is_empty() {
        if let Some(result) = crate::features::client_secret_audit::executor::execute(
            target_url,
            client,
            &template.client_secret_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }
    if !template.dom_redirect_audit.is_empty() {
        if let Some(result) = crate::features::dom_redirect_audit::executor::execute(
            target_url,
            client,
            &template.dom_redirect_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 22: Content Security Policy & CORS
    if !template.cors_audit.is_empty() {
        if let Some(result) = crate::features::cors_audit::executor::execute(
            target_url,
            client,
            &template.cors_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }
    if !template.csp_audit.is_empty() {
        if let Some(result) = crate::features::csp_audit::executor::execute(
            target_url,
            client,
            &template.csp_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 23: WAF Rule Validation
    if !template.waf_bypass_verify.is_empty() {
        if let Some(result) = crate::features::waf_bypass_verify::executor::execute(
            &target_host,
            client,
            &template.waf_bypass_verify,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }
    if !template.header_scorecard.is_empty() {
        if let Some(result) = crate::features::header_scorecard::executor::execute(
            target_url,
            client,
            &template.header_scorecard,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 24: Threat Intelligence & IP Reputation
    if !template.reputation_audit.is_empty() {
        if let Some(result) = crate::features::reputation_audit::executor::execute(
            &template.reputation_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }
    if !template.ct_log_audit.is_empty() {
        if let Some(result) = crate::features::ct_log_audit::executor::execute(
            &template.ct_log_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
            client,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 25: Automated Reporting & Remediation Generation
    // Note: Remediation Generation is now handled in the outer wrapper if needed.
    // Phase 26: Container & Kubernetes Security Auditing
    if !template.container_audit.is_empty() {
        if let Some(result) = crate::features::container_audit::executor::execute(
            &template.container_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }
    if !template.k8s_audit.is_empty() {
        if let Some(result) = crate::features::k8s_audit::executor::execute(
            &template.k8s_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 27: Source Code & Secrets Scanning (SAST)
    if !template.sast_taint.is_empty() {
        if let Some(result) = crate::features::sast_taint::executor::execute(
            &template.sast_taint,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }
    if !template.sast_secrets.is_empty() {
        if let Some(result) = crate::features::sast_secrets::executor::execute(
            &template.sast_secrets,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 28: Network & Port Security
    if !template.subdomain_takeover.is_empty() {
        if let Some(result) = crate::features::subdomain_takeover::executor::execute(
            &target_host,
            &template.subdomain_takeover,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }
    if !template.port_scan.is_empty() {
        if let Some(result) = crate::features::port_scan::executor::execute(
            &target_host,
            &template.port_scan,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 29: API Schema Compliance & Data Privacy
    if !template.pii_leak_audit.is_empty() {
        if let Some(result) = crate::features::pii_leak_audit::executor::execute(
            target_url,
            client,
            &template.pii_leak_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 30: CI/CD Pipeline & Supply Chain Security
    if !template.cicd_audit.is_empty() {
        if let Some(result) = crate::features::cicd_audit::executor::execute(
            &template.cicd_audit,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }
    
    // Phase 31: Schema Drift / Shadow API detection
    if !template.schema_drift.is_empty() {
        if let Some(result) = crate::features::schema_drift::executor::execute(
            target_url,
            client,
            &template.schema_drift,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    None
}

#[deprecated(note = "Use ScanExecutor with PluginRegistry instead. This is maintained for valayam-platform backward compatibility.")]
pub async fn execute_template(
    client: &StealthHttpClient,
    target_url: &str,
    template: VulnerabilityTemplate,
    rate_limiter: Option<&RateLimiter>,
) -> Option<FindingOwned> {
    let result = execute_template_inner(client, target_url, &template, rate_limiter).await;

    if let Some(res) = result {
        if !template.mitre_mapping.is_empty() {
            if let Some(_mitre_res) = crate::features::mitre_mapping::executor::execute(
                &template.mitre_mapping,
                &template.id,
                &template.info as &dyn TemplateMetadata,
                vec![res.clone()],
            ).await {
                // For MVP, we ignore the modified return to avoid complex ownership logic
            }
        }
        if !template.remediation_gen.is_empty() {
            if let Some(_rem_res) = crate::features::remediation_gen::executor::execute(
                &template.remediation_gen,
                &template.id,
                &template.info as &dyn TemplateMetadata,
                vec![res.clone()],
            ).await {
                // Similarly ignore modified return
            }
        }
        return Some(res);
    }
    
    None
}
