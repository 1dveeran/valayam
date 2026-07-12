use crate::core::rate_limiter::RateLimiter;
use crate::core::result::ScanResult;
use crate::core::variables::build_initial_context;
use crate::features::{dns_audit, http_scan, network_scan, scripting, tls_audit};
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
pub async fn execute_template(
    client: &StealthHttpClient,
    target_url: &str,
    template: VulnerabilityTemplate,
    rate_limiter: Option<&RateLimiter>,
) -> Option<ScanResult> {
    // Derive the bare hostname once for slices that need it
    let target_host = Url::parse(target_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| target_url.to_string());

    // Build the shared variable context seeded with built-in variables
    let mut variables = build_initial_context(target_url, &target_host);

    // Phase 1: HTTP Requests (with extractors & helpers)
    if !template.requests.is_empty() {
        if let Some(rl) = rate_limiter {
            rl.acquire().await;
        }

        if let Some(result) = http_scan::executor::execute(
            client,
            target_url,
            &template.requests,
            &template.id,
            &template.info,
            &mut variables,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 2: Network Scanning (TCP with banner grabbing)
    if !template.network.is_empty() {
        if let Some(result) = network_scan::executor::execute(
            target_url,
            &target_host,
            &template.network,
            &template.id,
            &template.info,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 3: DNS Auditing
    if !template.dns.is_empty() {
        if let Some(result) = dns_audit::executor::execute(
            &template.dns,
            &template.id,
            &template.info,
            &variables,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 4: TLS Certificate Auditing
    if !template.tls.is_empty() {
        if let Some(result) = tls_audit::executor::execute(
            &template.tls,
            &template.id,
            &template.info,
            &variables,
        )
        .await
        {
            return Some(result);
        }
    }

    // Phase 5: Script Execution (Rhai)
    if !template.scripts.is_empty() {
        if let Some(result) = scripting::executor::execute(
            target_url,
            &target_host,
            &template.scripts,
            &template.id,
            &template.info,
        )
        .await
        {
            return Some(result);
        }
    }

    None
}
