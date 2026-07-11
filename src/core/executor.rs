use crate::core::result::ScanResult;
use crate::matchers::stream_eval::ModernMatcher;
use crate::protocols::http::StealthHttpClient;
use crate::protocols::tcp::scan_ports;
use crate::templates::parser::{ScriptSource, VulnerabilityTemplate};
use crate::templates::script::ScriptEngine;
use chrono::Utc;
use std::collections::BTreeMap;
use std::sync::Arc;
use url::Url;

#[derive(Clone)]
pub struct ScanExecutor {
    client: Arc<StealthHttpClient>,
}

impl ScanExecutor {
    pub fn new(client: Arc<StealthHttpClient>) -> Self {
        Self { client }
    }

    /// Replaces variables like {{BaseURL}} with the actual target URL string
    fn resolve_payload(template_str: &str, target_url: &str) -> String {
        let clean_target = target_url.trim_end_matches('/');
        template_str.replace("{{BaseURL}}", clean_target)
    }

    pub async fn execute_scan(
        &self,
        target_url: &str,
        template: VulnerabilityTemplate,
    ) -> Option<ScanResult> {
        // --- HTTP Requests ---
        for req_rule in &template.requests {
            let resolved_path = Self::resolve_payload(&req_rule.path, target_url);

            let Ok(resp) = self
                .client
                .send_request(
                    target_url,
                    &req_rule.method,
                    &resolved_path,
                    req_rule.headers.as_ref(),
                )
                .await
            else {
                continue; // Silently skip connection timeouts/failures
            };

            let status = resp.status().as_u16();
            let Ok(body_bytes) = resp.bytes().await else {
                continue;
            };

            let all_matchers_succeeded = if req_rule.matchers.is_empty() {
                false
            } else {
                req_rule.matchers.iter().all(|matcher| {
                    if matcher.r#type == "regex" && matcher.part == "body" {
                        ModernMatcher::evaluate_stream(&body_bytes, &matcher.regex)
                    } else if matcher.r#type == "status" && matcher.part == "status" {
                        matcher
                            .status
                            .as_ref()
                            .is_some_and(|s| s.contains(&status))
                    } else {
                        false
                    }
                })
            };

            if all_matchers_succeeded {
                return Some(ScanResult {
                    timestamp: Utc::now(),
                    template_id: template.id,
                    template_name: template.info.name,
                    template_severity: template.info.severity,
                    target: target_url.to_string(),
                    payload: resolved_path,
                });
            }
        }

        // --- Network Requests ---
        let target_host = Url::parse(target_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| target_url.to_string());

        for net_rule in &template.network {
            let host_to_scan = net_rule.host.replace("{{Hostname}}", &target_host);
            let open_ports = scan_ports(&host_to_scan, &net_rule.ports).await;

            // Phase 1: Any open port is a finding if no matchers are specified.
            // Matcher logic for banner grabbing will be added in a future phase.
            if net_rule.matchers.is_empty() {
                if let Some(first_open_port) = open_ports.into_iter().next() {
                    return Some(ScanResult {
                        timestamp: Utc::now(),
                        template_id: template.id.clone(),
                        template_name: template.info.name.clone(),
                        template_severity: template.info.severity.clone(),
                        target: host_to_scan,
                        payload: first_open_port.to_string(),
                    });
                }
            }
        }

        // --- Script Execution ---
        for script_rule in &template.scripts {
            // Only support the "rhai" engine for now; skip unknown engines gracefully
            let "rhai" = script_rule.engine.as_str() else {
                eprintln!(
                    "[!] Unsupported script engine: '{}'. Skipping.",
                    script_rule.engine
                );
                continue;
            };

            // Resolve script source: inline code or read from file
            let script_code = match &script_rule.source {
                ScriptSource::Inline { code } => code.clone(),
                ScriptSource::File { path } => {
                    let Ok(contents) = std::fs::read_to_string(path) else {
                        eprintln!("[!] Failed to read script file: '{}'. Skipping.", path);
                        continue;
                    };
                    contents
                }
            };

            // Build the variables map to inject into the script's scope
            let mut variables = BTreeMap::new();
            let clean_target = target_url.trim_end_matches('/').to_string();
            variables.insert("target_url".to_string(), clean_target);
            variables.insert("base_url".to_string(), target_url.to_string());
            variables.insert("hostname".to_string(), target_host.clone());

            // Clone what we need for the blocking closure
            let template_id = template.id.clone();
            let template_name = template.info.name.clone();
            let template_severity = template.info.severity.clone();
            let target_owned = target_url.to_string();

            // Bridge sync Rhai eval into the async runtime via spawn_blocking
            let handle = tokio::task::spawn_blocking(move || {
                let Ok(engine) = ScriptEngine::new() else {
                    eprintln!("[!] Failed to initialize Rhai engine.");
                    return None;
                };

                match engine.execute(&script_code, &variables) {
                    Ok(true) => Some(ScanResult {
                        timestamp: Utc::now(),
                        template_id,
                        template_name,
                        template_severity,
                        target: target_owned,
                        payload: "[script finding]".to_string(),
                    }),
                    Ok(false) => None,
                    Err(e) => {
                        eprintln!("[!] Script execution error: {}", e);
                        None
                    }
                }
            });

            let Ok(result) = handle.await else { continue };
            if result.is_some() {
                return result;
            }
        }

        None
    }
}
