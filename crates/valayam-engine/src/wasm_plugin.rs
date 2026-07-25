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

    fn is_applicable(&self, _template: &valayam_models::templates::schema::VulnerabilityTemplate) -> bool {
        true
    }

    async fn init(&self) -> Result<(), ScannerError> {
        let wasm = Wasm::file(&self.wasm_path);
        let mut manifest = Manifest::new([wasm]);
        manifest.allowed_paths = Some(std::collections::BTreeMap::from([(
            "/".to_string(),
            PathBuf::from("/"),
        )]));
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
                if json.get("matched").and_then(|v| v.as_bool()).unwrap_or(false) {
                    let count = json.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

                    if let Some(findings) = json.get("findings").and_then(|v| v.as_array()) {
                        for finding_val in findings {
                            if let Ok(finding) = serde_json::from_value::<FindingOwned>(finding_val.clone()) {
                                let _ = ctx.finding_tx.send(finding).await;
                            }
                        }
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