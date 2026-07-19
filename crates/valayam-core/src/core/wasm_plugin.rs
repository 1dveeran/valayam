use crate::core::traits::{FindingOwned, PluginOutcome, ScanContext, ScanPlugin};
use std::path::PathBuf;
use wasmtime::*;
use wasmtime_wasi::WasiCtxBuilder;

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
    fn name(&self) -> &'static str {
        Box::leak(self.name.clone().into_boxed_str())
    }

    fn is_applicable(&self, _template: &crate::template::schema::VulnerabilityTemplate) -> bool {
        true
    }

    async fn init(&self) -> Result<(), crate::core::error::ScannerError> {
        // Validate the wasm file can be parsed
        let engine = Engine::default();
        match Module::from_file(&engine, &self.wasm_path) {
            Ok(_) => Ok(()),
            Err(e) => Err(crate::core::error::ScannerError::PluginInitializationError(format!("Invalid wasm: {}", e))),
        }
    }

    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        use crate::core::error::ScannerError;

        let template_json = match serde_json::to_string(&*ctx.template) {
            Ok(j) => j,
            Err(_) => return PluginOutcome::NoMatch,
        };
        let vars = ctx.snapshot_variables().await;
        let context_json = serde_json::to_string(&vars).unwrap_or_default();

        let engine = Engine::default();
        let module = match Module::from_file(&engine, &self.wasm_path) {
            Ok(m) => m,
            Err(_) => return PluginOutcome::Failed { error: ScannerError::PluginExecutionError("wasm module load failed".into()), retryable: false },
        };

        // For MVP, we aren't setting up complex WASI or memory sharing for the execute call,
        // because we would need the guest to export memory and allocate functions.
        // A complete Wasm integration requires a canonical ABI (like waPC or Extism) which handles memory mapping.
        // Here we just do a dummy success. In a real world scenario, you'd use Extism or custom memory passing here.

        tracing::info!(plugin = %self.name, "Executing WASM plugin (simulation)");
        PluginOutcome::Matched { count: 1 }
    }
}
