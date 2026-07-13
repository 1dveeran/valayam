use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::engine::ScriptEngine;
use super::parser::{ScriptSource, ScriptTemplate};
use chrono::Utc;
use std::collections::HashMap;

/// Executes all script rules from a template against the target.
/// Returns the first finding (ScanResult) or None if no scripts triggered.
pub async fn execute(
    target_url: &str,
    target_host: &str,
    scripts: &[ScriptTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
    variables_in: &HashMap<String, String>,
) -> Option<ScanResult> {
    for script_rule in scripts {
        // Only support the "rhai" engine for now; skip unknown engines gracefully
        let "rhai" = script_rule.engine.as_str() else {
            tracing::warn!("Unsupported script engine: '{}'. Skipping.", script_rule.engine);
            continue;
        };

        // Resolve script source: inline code or read from file
        let script_code = match &script_rule.source {
            ScriptSource::Inline { code } => code.clone(),
            ScriptSource::File { path } => {
                let Ok(contents) = std::fs::read_to_string(path) else {
                    tracing::error!("Failed to read script file: '{}'. Skipping.", path);
                    continue;
                };
                contents
            }
        };

        // Clone variables to inject into the script's scope
        let mut variables = variables_in.clone();
        let clean_target = target_url.trim_end_matches('/').to_string();
        variables.insert("target_url".to_string(), clean_target);
        variables.insert("base_url".to_string(), target_url.to_string());
        variables.insert("hostname".to_string(), target_host.to_string());

        // Clone what we need for the blocking closure
        let template_id = template_id.to_string();
        let template_name = template_info.name.clone();
        let template_severity = template_info.severity.clone();
        let target_owned = target_url.to_string();

        // Bridge sync Rhai eval into the async runtime via spawn_blocking
        tracing::debug!(target = %target_url, engine = %script_rule.engine, "Executing script");
        let handle = tokio::task::spawn_blocking(move || {
            let Ok(engine) = ScriptEngine::new() else {
                tracing::error!("Failed to initialize Rhai engine.");
                return None;
            };

            match engine.execute(&script_code, &mut variables) {
                Ok(true) => {
                    tracing::debug!(target = %target_owned, "Vulnerability script match found");
                    Some(ScanResult {
                        timestamp: Utc::now(),
                        template_id,
                        template_name,
                        template_severity,
                        target: target_owned,
                        payload: "[script finding]".to_string(),
                    })
                },
                Ok(false) => {
                    tracing::trace!("Script executed successfully but returned false");
                    None
                },
                Err(e) => {
                    tracing::error!("Script execution error: {}", e);
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
