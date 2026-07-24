use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use super::engine::ScriptEngine;
use valayam_models::templates::scripting::{ScriptSource, ScriptTemplate};
use std::collections::HashMap;

/// Executes all script rules from a template against the target.
/// Returns the first finding (ScanResult) or None if no scripts triggered.
pub async fn execute(
    target_url: &str,
    target_host: &str,
    scripts: &[ScriptTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
    variables_in: &HashMap<String, String>,
) -> Option<FindingOwned> {
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
        let template_name = template_meta.template_name().to_string();
        let template_severity = template_meta.template_severity().to_string();
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
                    let mut meta = HashMap::new();
                    meta.insert("template_id".to_string(), template_id);
                    meta.insert("template_name".to_string(), template_name);
                    meta.insert("template_severity".to_string(), template_severity);
                    Some(FindingOwned::from_template(target_owned, "Rhai script execution matched", meta))
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
