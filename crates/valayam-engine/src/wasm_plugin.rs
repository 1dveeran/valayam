use valayam_models::error::ScannerError;
use crate::traits::{FindingOwned, PluginOutcome, ScanContext, ScanPlugin};
use std::path::PathBuf;
use extism::{Plugin, Manifest, Wasm};

/// WASM ABI contract for Valayam plugins via Extism.
///
/// Guest modules must use the `valayam-plugin-sdk` (extism-pdk) to export
/// an `execute_scan` function.
///
/// The input JSON format: `{"template":{...},"context":{...}}`
/// The result JSON format: `{"matched":true,"count":N,"findings":[...]}` or `{"matched":false}`
pub struct WasmPluginBridge {
    name: String,
    wasm_path: PathBuf,
}

impl WasmPluginBridge {
    pub fn new(name: impl Into<String>, wasm_path: PathBuf) -> Self {
        Self {
            name: name.into(),
            wasm_path,
        }
    }
}

#[async_trait::async_trait]
impl ScanPlugin for WasmPluginBridge {
    fn name(&self) -> &str {
        &self.name
    }

    /// A WASM plugin is only applicable to a template if the template explicitly declares
    /// the plugin's corresponding section. This prevents plugins like `cors-audit` from
    /// running against every template and producing false/duplicate findings.
    ///
    /// The match is done by normalising the plugin name (strip `.wasm`, replace `_` with `-`)
    /// and checking via the trait-based `has_section()` method.
    fn is_applicable(&self, template: &valayam_models::templates::schema::VulnerabilityTemplate) -> bool {
        // Normalise: "cors-audit.wasm" → "cors-audit", "cors_audit.wasm" → "cors-audit"
        let normalised = self.name
            .trim_end_matches(".wasm")
            .replace('_', "-")
            .to_lowercase();

        match normalised.as_str() {
            // Well-known: check if template has a matching section by kebab-case name
            n if template.has_section(n) => true,
            // Unknown WASM plugin: opt-in by default (backwards compatible for custom plugins)
            _ => {
                tracing::debug!(
                    plugin = %self.name,
                    "Unknown WASM plugin '{}'; running against all templates",
                    self.name
                );
                true
            }
        }
    }

    async fn init(&self) -> Result<(), ScannerError> {
        let wasm = Wasm::file(&self.wasm_path);
        let mut manifest = Manifest::new([wasm]);
        manifest.allowed_paths = Some(std::collections::BTreeMap::from([(
            "/".to_string(),
            PathBuf::from("/"),
        )]));
        manifest.allowed_hosts = Some(vec!["*".to_string()]);
        if let Err(e) = Plugin::new(&manifest, [], true) {
            return Err(ScannerError::PluginInitializationError(
                format!("Failed to load Wasm via Extism '{}': {}", self.wasm_path.display(), e)
            ));
        }
        Ok(())
    }

    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        let template_json = match serde_json::to_string(&*ctx.template) {
            Ok(j) => j,
            Err(_) => return PluginOutcome::NoMatch,
        };
        let vars = ctx.snapshot_variables().await;
        let context_json = serde_json::to_string(&vars).unwrap_or_default();

        let input_json = format!(
            r#"{{"template":{},"context":{}}}"#,
            template_json, context_json
        );

        let wasm = Wasm::file(&self.wasm_path);
        let mut manifest = Manifest::new([wasm]);
        manifest.allowed_paths = Some(std::collections::BTreeMap::from([(
            "/".to_string(),
            PathBuf::from("/"),
        )]));
        manifest.allowed_hosts = Some(vec!["*".to_string()]);
        let mut plugin = match extism::PluginBuilder::new(manifest)
            .with_wasi(true)
            .with_function(
                "dns_resolve",
                [extism::ValType::I64],
                [extism::ValType::I64],
                extism::UserData::new(()),
                crate::host_functions::dns_resolve
            )
            .with_function(
                "kv_get",
                [extism::ValType::I64],
                [extism::ValType::I64],
                extism::UserData::new(()),
                crate::host_functions::kv_get
            )
            .with_function(
                "kv_set",
                [extism::ValType::I64],
                [extism::ValType::I64],
                extism::UserData::new(()),
                crate::host_functions::kv_set
            )
            .build()
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(plugin = %self.name, error = %e, "wasm module load failed");
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError(format!("wasm load: {}", e)),
                    retryable: false,
                };
            }
        };

        let output_bytes = match plugin.call::<&str, Vec<u8>>("execute_scan", &input_json) {
            Ok(output) => output,
            Err(e) => {
                tracing::error!(plugin = %self.name, error = %e, "wasm execute failed");
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError(format!("wasm execute: {}", e)),
                    retryable: false,
                };
            }
        };

        let result_str = match std::str::from_utf8(&output_bytes) {
            Ok(s) => s,
            Err(_) => return PluginOutcome::NoMatch,
        };

        match serde_json::from_str::<serde_json::Value>(result_str) {
            Ok(json) => {
                tracing::debug!("WASM OUTPUT JSON: {}", result_str);
                if json.get("matched").and_then(|v| v.as_bool()).unwrap_or(false) {
                    let count = json.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

                    if let Some(findings) = json.get("findings").and_then(|v| v.as_array()) {
                        for finding_val in findings {
                                match serde_json::from_value::<FindingOwned>(finding_val.clone()) {
                                    Ok(mut finding) => {
                                        finding.template_id = ctx.template.id.clone();
                                        finding.template_name = ctx.template.info.name.clone();
                                        let _ = ctx.finding_tx.send(finding).await;
                                    }
                                Err(e) => {
                                    tracing::error!("Failed to deserialize finding {}: {:?}", e, finding_val);
                                }
                            }
                        }
                    } else {
                        tracing::error!("findings missing or not array in WasmOutput");
                    }

                    PluginOutcome::Matched { count }
                } else {
                    PluginOutcome::NoMatch
                }
            }
            Err(e) => {
                tracing::warn!(plugin = %self.name, error = %e, result = %result_str, "wasm plugin returned unparseable result");
                PluginOutcome::NoMatch
            }
        }
    }
}