use crate::core::error::ScannerError;
use crate::core::traits::{FindingOwned, PluginOutcome, ScanContext, ScanPlugin};
use std::path::PathBuf;
use wasmtime::*;

/// WASM ABI contract for Valayam plugins.
///
/// Guest modules must export:
/// - `memory` — the module's linear memory
/// - `valayam_alloc(size: i32) -> i32` — allocate `size` bytes, return offset
/// - `valayam_execute(input_offset: i32, input_len: i32) -> i32` — execute scan,
///   returns offset in memory where the null-terminated result JSON begins
///
/// The input JSON format: `{"template":{...},"context":{...}}`
/// The result JSON format: `{"matched":true,"count":N,"findings":[...]}` or `{"matched":false}`
pub struct WasmPluginBridge {
    name: String,
    wasm_path: PathBuf,
    engine: Engine,
    module: Module,
}

impl WasmPluginBridge {
    pub fn new(name: impl Into<String>, wasm_path: PathBuf) -> Self {
        let mut config = Config::new();
        // Enable WASM resource limits (fuel)
        config.consume_fuel(true);

        let engine = Engine::new(&config).unwrap_or_default();
        // At construction time we attempt to compile; if it fails we still construct
        // so init() can report the error with proper ScannerError type.
        let module = Module::from_file(&engine, &wasm_path).unwrap_or_else(|e| {
            tracing::warn!("Failed to load WASM module from {}: {}", wasm_path.display(), e);
            // Create a minimal dummy module for error path — we validate in init()
            Module::new(&engine, [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]).expect("Empty module should always succeed")
        });
        Self {
            name: name.into(),
            wasm_path,
            engine,
            module,
        }
    }
}

#[async_trait::async_trait]
impl ScanPlugin for WasmPluginBridge {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_applicable(&self, _template: &crate::template::schema::VulnerabilityTemplate) -> bool {
        // Check if the module exports the required function
        self.module.get_export("valayam_execute").is_some()
    }

    async fn init(&self) -> Result<(), ScannerError> {
        // Validate the wasm file can be parsed and has required exports
        let module = Module::from_file(&self.engine, &self.wasm_path)
            .map_err(|e| ScannerError::PluginInitializationError(
                format!("Invalid wasm module '{}': {}", self.wasm_path.display(), e)
            ))?;

        // Check required exports
        if module.get_export("valayam_execute").is_none() {
            return Err(ScannerError::PluginInitializationError(
                format!("WASM plugin '{}' is missing required export 'valayam_execute'", self.name)
            ));
        }
        if module.get_export("valayam_alloc").is_none() {
            return Err(ScannerError::PluginInitializationError(
                format!("WASM plugin '{}' is missing required export 'valayam_alloc'", self.name)
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

        // Build combined input: {"template":..., "context":...}
        let input_json = format!(
            r#"{{"template":{},"context":{}}}"#,
            template_json, context_json
        );
        let input_bytes = input_json.as_bytes();
        let input_len = input_bytes.len() as i32;

        // Create a fresh instance per execute (thread-safe, no shared state)
        let module = match Module::from_file(&self.engine, &self.wasm_path) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(plugin = %self.name, error = %e, "wasm module reload failed");
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError(format!("wasm reload: {}", e)),
                    retryable: false,
                };
            }
        };

        let mut linker = Linker::new(&self.engine);
        if let Err(e) = wasmtime_wasi::add_to_linker(&mut linker, |s| s) {
            tracing::error!(plugin = %self.name, error = %e, "failed to add wasi to linker");
            return PluginOutcome::Failed {
                error: ScannerError::PluginExecutionError(format!("wasi linker: {}", e)),
                retryable: false,
            };
        }

        let wasi = wasmtime_wasi::WasiCtxBuilder::new().build();
        let mut store = Store::new(&self.engine, wasi);
        
        // Apply CPU cycle limit (Fuel) to prevent infinite loops (DoS protection)
        if let Err(e) = store.set_fuel(100_000_000) {
            tracing::error!(plugin = %self.name, error = %e, "failed to set fuel limit");
        }

        let instance = match linker.instantiate(&mut store, &module) {
            Ok(i) => i,
            Err(e) => {
                tracing::error!(plugin = %self.name, error = %e, "wasm instantiation failed (fuel exhausted?)");
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError(format!("wasm instantiate: {}", e)),
                    retryable: false,
                };
            }
        };

        // Get memory export
        let memory = match instance.get_memory(&mut store, "memory") {
            Some(m) => m,
            None => {
                tracing::error!(plugin = %self.name, "WASM plugin missing 'memory' export");
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError("missing memory export".into()),
                    retryable: false,
                };
            }
        };

        // Get alloc function
        let alloc_fn = match instance.get_typed_func::<i32, i32>(&mut store, "valayam_alloc") {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(plugin = %self.name, error = %e, "wasm alloc function not found");
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError(format!("wasm alloc: {}", e)),
                    retryable: false,
                };
            }
        };

        // Allocate guest memory for input data (with 1 byte extra for null terminator)
        let input_offset = match alloc_fn.call(&mut store, (input_len + 1) as i32) {
            Ok(offset) => offset,
            Err(e) => {
                tracing::error!(plugin = %self.name, error = %e, "wasm alloc failed");
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError(format!("wasm alloc: {}", e)),
                    retryable: true,
                };
            }
        };

        // Write input data to guest memory
        if let Err(e) = memory.write(&mut store, input_offset as usize, input_bytes) {
            tracing::error!(plugin = %self.name, error = %e, "wasm memory write failed");
            return PluginOutcome::Failed {
                error: ScannerError::PluginExecutionError(format!("memory write: {}", e)),
                retryable: false,
            };
        }

        // Call execute function
        let execute_fn = match instance.get_typed_func::<(i32, i32), i32>(&mut store, "valayam_execute") {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(plugin = %self.name, error = %e, "wasm execute export not found");
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError(format!("wasm execute: {}", e)),
                    retryable: false,
                };
            }
        };

        let result_offset = match execute_fn.call(&mut store, (input_offset, input_len)) {
            Ok(offset) => offset,
            Err(e) => {
                tracing::error!(plugin = %self.name, error = %e, "wasm execute failed");
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError(format!("wasm execute: {}", e)),
                    retryable: false,
                };
            }
        };

        // Read result string from guest memory (null-terminated)
        let result_bytes = match read_null_terminated(&memory, &store, result_offset as usize) {
            Some(b) => b,
            None => {
                tracing::error!(plugin = %self.name, "wasm execute returned invalid result offset");
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError("invalid result offset".into()),
                    retryable: false,
                };
            }
        };

        // Parse result JSON
        let result_str = match std::str::from_utf8(&result_bytes) {
            Ok(s) => s,
            Err(_) => return PluginOutcome::NoMatch,
        };

        match serde_json::from_str::<serde_json::Value>(result_str) {
            Ok(json) => {
                if json.get("matched").and_then(|v| v.as_bool()).unwrap_or(false) {
                    let count = json.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

                    // Process individual findings if present
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

/// Read a null-terminated byte sequence from wasm linear memory at the given offset.
/// Returns `None` if the memory read fails or no null terminator is found within 64KB.
fn read_null_terminated(
    memory: &Memory,
    store: impl AsContext,
    offset: usize,
) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 65536];
    memory.read(store, offset, &mut buf).ok()?;
    let end = buf.iter().position(|&b| b == 0)?;
    Some(buf[..end].to_vec())
}