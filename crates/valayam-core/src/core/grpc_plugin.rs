use crate::core::traits::{FindingOwned, PluginOutcome, ScanContext, ScanPlugin};
use crate::plugin_rpc::plugin_service_client::PluginServiceClient;
use crate::plugin_rpc::{ExecuteRequest, InitRequest, ShutdownRequest, ValidateConfigRequest};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tonic::transport::Channel;

pub struct GrpcPluginBridge {
    name: String,
    exe_path: PathBuf,
    client: tokio::sync::RwLock<Option<PluginServiceClient<Channel>>>,
    child_process: tokio::sync::Mutex<Option<Child>>,
}

impl GrpcPluginBridge {
    pub fn new(name: impl Into<String>, exe_path: PathBuf) -> Self {
        Self {
            name: name.into(),
            exe_path,
            client: tokio::sync::RwLock::new(None),
            child_process: tokio::sync::Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl ScanPlugin for GrpcPluginBridge {
    fn name(&self) -> &'static str {
        // We leak the string to get a &'static str because the trait requires it.
        // In a real implementation we might change the trait to return &str or Cow.
        Box::leak(self.name.clone().into_boxed_str())
    }

    fn is_applicable(&self, _template: &crate::template::schema::VulnerabilityTemplate) -> bool {
        // By default, the bridge doesn't know until we call execute or validate.
        // We assume it's applicable and let it NoMatch during execute.
        true
    }

    async fn init(&self) -> Result<(), crate::core::error::ScannerError> {
        use crate::core::error::ScannerError;

        let mut cmd;
        if let Some(ext) = self.exe_path.extension().and_then(|e| e.to_str()) {
            if ext == "py" {
                // Determine OS specific python command
                #[cfg(target_os = "windows")]
                { cmd = Command::new("python"); }
                #[cfg(not(target_os = "windows"))]
                { cmd = Command::new("python3"); }
                
                cmd.arg(&self.exe_path);
            } else if ext == "bat" || ext == "cmd" {
                cmd = Command::new("cmd");
                cmd.args(["/C", self.exe_path.to_str().unwrap()]);
            } else {
                cmd = Command::new(&self.exe_path);
            }
        } else {
            cmd = Command::new(&self.exe_path);
        }

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| ScannerError::PluginInitializationError(format!("Failed to spawn plugin: {}", e)))?;

        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout).lines();

        // Wait for the HashiCorp-style handshake line
        // Format: 1|plugin|tcp|127.0.0.1:<PORT>|grpc
        let mut port = None;
        while let Ok(Some(line)) = tokio::time::timeout(Duration::from_secs(10), reader.next_line()).await.map_err(|_| ScannerError::PluginInitializationError("Timeout waiting for plugin handshake".into()))? {
            if line.starts_with("1|") && line.contains("|grpc") {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() >= 4 {
                    let addr = parts[3]; // 127.0.0.1:PORT
                    port = Some(addr.to_string());
                    break;
                }
            } else {
                tracing::debug!(plugin = %self.name, "stdout: {}", line);
            }
        }

        let addr = port.ok_or_else(|| ScannerError::PluginInitializationError("Plugin failed to output gRPC port".into()))?;
        let endpoint = format!("http://{}", addr);

        // Connect tonic client
        let channel = Channel::from_shared(endpoint)
            .map_err(|e| ScannerError::PluginInitializationError(format!("Invalid plugin endpoint: {}", e)))?
            .connect()
            .await
            .map_err(|e| ScannerError::PluginInitializationError(format!("Failed to connect to plugin: {}", e)))?;

        let mut client = PluginServiceClient::new(channel);

        // Call remote Init
        let res = client.init(InitRequest {}).await
            .map_err(|e| ScannerError::PluginInitializationError(format!("RPC Init failed: {}", e)))?;

        if !res.into_inner().success {
            return Err(ScannerError::PluginInitializationError("Plugin rejected init".into()));
        }

        // Store child process and client
        *self.child_process.lock().await = Some(child);
        *self.client.write().await = Some(client);

        Ok(())
    }

    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        use crate::core::error::ScannerError;

        let client_opt = self.client.read().await;
        if client_opt.is_none() {
            return PluginOutcome::Failed {
                error: ScannerError::PluginExecutionError("Plugin not initialized".into()),
                retryable: true,
            };
        }
        let mut client = client_opt.as_ref().unwrap().clone();

        let template_json = match serde_json::to_string(&*ctx.template) {
            Ok(j) => j,
            Err(_) => return PluginOutcome::NoMatch, // or error
        };

        let vars = ctx.snapshot_variables().await;
        let context_json = serde_json::to_string(&vars).unwrap_or_default();

        let req = ExecuteRequest {
            template_json,
            target: ctx.target.clone(),
            target_host: ctx.target_host.clone(),
            context_json,
        };

        let mut count = 0;
        match client.execute(req).await {
            Ok(response) => {
                let mut stream = response.into_inner();
                while let Ok(Some(resp)) = stream.message().await {
                    if let Ok(finding) = serde_json::from_str::<FindingOwned>(&resp.finding_json) {
                        let _ = ctx.finding_tx.send(finding).await;
                        count += 1;
                    }
                }
            }
            Err(e) => {
                return PluginOutcome::Failed {
                    error: ScannerError::PluginExecutionError(format!("RPC execute failed: {}", e)),
                    retryable: false,
                };
            }
        }

        if count > 0 {
            PluginOutcome::Matched { count }
        } else {
            PluginOutcome::NoMatch
        }
    }

    async fn shutdown(&self) -> Result<(), crate::core::error::ScannerError> {
        let mut client_guard = self.client.write().await;
        if let Some(mut client) = client_guard.take() {
            let _ = client.shutdown(ShutdownRequest {}).await;
        }

        let mut child_guard = self.child_process.lock().await;
        if let Some(mut child) = child_guard.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        
        Ok(())
    }
}
