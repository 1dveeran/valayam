use crate::cli::Args;
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use valayam_core::core::rate_limiter::RateLimiter;
use valayam_core::core::registry::PluginRegistry;
use valayam_core::core::executor::ScanExecutor;
use valayam_core::core::traits::{FindingOwned, Reporter};
use valayam_core::core::reporters::{console::ConsoleReporter, json::JsonReporter, composite::CompositeReporter};
use valayam_core::core::plugins::*;
use valayam_core::features::nuclei_compat::executor::NucleiExecutor;
use valayam_core::features::nuclei_compat::parser::NucleiTemplate;
use valayam_core::network::http::StealthHttpClient;
use valayam_core::rpc::scanner_client::ScannerClient;
use valayam_core::template::schema::VulnerabilityTemplate;

pub async fn run_scan(
    args: Args,
    template_files: Vec<PathBuf>,
    is_nuclei: bool,
    targets: Vec<String>,
    http_client: Arc<StealthHttpClient>,
    executor_nuclei: NucleiExecutor,
    rate_limiter: Option<Arc<RateLimiter>>,
    grpc_client: Option<ScannerClient<tonic::transport::Channel>>,
) -> anyhow::Result<()> {
    let spinner = ProgressBar::new_spinner();
    spinner.enable_steady_tick(Duration::from_millis(120));
    let style_result = ProgressStyle::with_template("{spinner:.blue} {msg}");
    if let Ok(style) = style_result {
        spinner.set_style(style.tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]));
    }
    spinner.set_message(format!("Scanning {} targets...", targets.len()));

    // ── 1. Create bounded MPSC channel ──
    let (finding_tx, mut finding_rx) = tokio::sync::mpsc::channel::<FindingOwned>(1000);

    // ── 2. Create cancellation token (wired to Ctrl+C) ──
    let cancel = CancellationToken::new();
    let _cancel_clone = cancel.clone();
    let cancel_for_handler = cancel.clone();
    
    // We will still handle ctrl-c to save state
    let db = crate::state::StateDB::new(".valayam_state").expect("Failed to initialize state DB");
    let state_id = args.resume.unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs().to_string());
    
    let mut actual_targets = targets.clone();
    if let Some((pending, _completed)) = db.load_state(&state_id).unwrap_or(None) {
        println!("[+] Resuming scan from state ID: {}. Loaded {} pending targets.", state_id, pending.len());
        actual_targets = pending;
    } else {
        println!("[+] Starting new scan with state ID: {}", state_id);
    }
    
    let pending_for_shutdown = actual_targets.clone();
    tokio::spawn(async move {
        if let Ok(_) = tokio::signal::ctrl_c().await {
            tracing::warn!("received Ctrl+C, initiating graceful shutdown...");
            let _ = db.save_state(&state_id, &pending_for_shutdown, &[]);
            cancel_for_handler.cancel();
        }
    });

    // ── 3. Build PluginRegistry ──
    let registry = {
        let reg = PluginRegistry::new();
        // Core protocols
        reg.register(HttpScanPlugin::new(http_client.clone()));
        reg.register(NetworkScanPlugin::new());
        reg.register(DnsAuditPlugin::new());
        reg.register(TlsAuditPlugin::new());
        reg.register(ScriptingPlugin::new());
        reg.register(FuzzerPlugin::new(http_client.clone()));
        // Cloud & Extended
        reg.register(CloudSecPlugin::new(http_client.clone()));
        reg.register(AuthLogicPlugin::new(http_client.clone()));
        reg.register(DeepAnalysisPlugin::new(http_client.clone()));
        reg.register(IacAuditPlugin::new());
        reg.register(SbomAuditPlugin::new(http_client.clone()));
        reg.register(GrpcAuditPlugin::new(http_client.clone()));
        reg.register(GraphqlAuditPlugin::new(http_client.clone()));
        reg.register(DriftDetectPlugin::new(http_client.clone()));
        reg.register(CredMonitorPlugin::new(http_client.clone()));
        reg.register(OauthAuditPlugin::new(http_client.clone()));
        reg.register(IdpAuditPlugin::new(http_client.clone()));
        reg.register(AwsEscalatePlugin::new(http_client.clone()));
        reg.register(AzureGcpEscalatePlugin::new(http_client.clone()));
        reg.register(BrowserAuditPlugin::new(http_client.clone()));
        reg.register(IotAuditPlugin::new());
        reg.register(ScadaAuditPlugin::new());
        reg.register(AutoRedteamPlugin::new());
        reg.register(ImplantDeployPlugin::new());
        reg.register(ClientSecretAuditPlugin::new(http_client.clone()));
        reg.register(DomRedirectAuditPlugin::new(http_client.clone()));
        reg.register(CorsAuditPlugin::new(http_client.clone()));
        reg.register(CspAuditPlugin::new(http_client.clone()));
        reg.register(WafBypassVerifyPlugin::new(http_client.clone()));
        reg.register(HeaderScorecardPlugin::new(http_client.clone()));
        reg.register(ReputationAuditPlugin::new());
        reg.register(CtLogAuditPlugin::new(http_client.clone()));
        reg.register(RemediationGenPlugin::new());
        reg.register(MitreMappingPlugin::new());
        reg.register(ContainerAuditPlugin::new());
        reg.register(K8sAuditPlugin::new());
        reg.register(SastTaintPlugin::new());
        reg.register(SastSecretsPlugin::new());
        reg.register(SubdomainTakeoverPlugin::new());
        reg.register(PortScanPlugin::new());
        reg.register(SchemaDriftPlugin::new(http_client.clone()));
        reg.register(PiiLeakAuditPlugin::new(http_client.clone()));
        reg.register(CicdAuditPlugin::new());
        reg.register(DependencyAuditPlugin::new());
        
        let reg_arc = Arc::new(reg);
        
        // Dynamically load external plugins from ./plugins directory and watch for hot-reloads
        let plugins_dir = std::path::Path::new("plugins");
        if plugins_dir.exists() {
            match reg_arc.clone().start_hot_reload(plugins_dir.to_path_buf()) {
                Ok(watcher) => {
                    // Leak the watcher into a lazy_static or simply let it run if it's stored.
                    // Wait, we need to keep it alive. We can store it in a static Mutex, or leak it.
                    // For a CLI that runs and exits, leaking is fine for the duration of the scan.
                    Box::leak(Box::new(watcher));
                    tracing::info!("Hot-reloading enabled for ./plugins");
                }
                Err(e) => tracing::warn!("Failed to start hot-reload for ./plugins: {}", e),
            }
        }
        
        reg_arc
    };

    // ── 4. Initialize all plugins (fail-fast on bad config) ──
    registry.init_all().await?;

    // ── 5. Build reporters ──
    let mut reporters: Vec<Box<dyn Reporter>> = vec![Box::new(ConsoleReporter)];
    if let Some(ref path) = args.output {
        // Assume jsonl for now. In a real app we might pick reporter based on args.format
        reporters.push(Box::new(JsonReporter::new(path)?));
    }
    let composite = CompositeReporter::new(reporters);

    // ── 6. Spawn Consumer task ──
    let consumer_handle = tokio::spawn(async move {
        let mut count = 0usize;
        while let Some(finding) = finding_rx.recv().await {
            if let Err(e) = composite.process_finding(&finding).await {
                tracing::error!(error = %e, "reporter failed");
            }
            count += 1;
        }
        let _ = composite.flush().await;
        count
    });

    // ── 7. Build Executor ──
    let executor = ScanExecutor::new(
        finding_tx.clone(),
        registry.clone(),
        rate_limiter.clone(),
        cancel.clone(),
    );

    let mut tasks = Vec::new();
    for target in &actual_targets {
        for file_path in &template_files {
            tasks.push((target.clone(), file_path.clone()));
        }
    }

    let concurrency = args.concurrency;
    let grpc_client_arc = grpc_client.map(Arc::new);

    let stream = futures::stream::iter(tasks).map(|(target_url, file_path_clone)| {
        let exec = executor.clone();
        let exec_nuclei = executor_nuclei.clone();
        let grpc_client_clone = grpc_client_arc.clone();
        let finding_tx_clone = finding_tx.clone();

        async move {
            let path_str = file_path_clone.to_string_lossy().to_string();

            if is_nuclei {
                let template = match NucleiTemplate::load(&file_path_clone) {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::error!("Failed to load Nuclei template {}: {}", path_str, e);
                        return;
                    }
                };
                if let Some(res) = exec_nuclei.execute_scan(&target_url, template).await {
                    // Nuclei executor returns legacy ScanResult. Convert it to FindingOwned.
                    let finding = valayam_core::core::scan_result_bridge::scan_result_to_finding(res);
                    let _ = finding_tx_clone.send(finding).await;
                }
            } else {
                if let Some(grpc_arc) = grpc_client_clone {
                    let mut client = (*grpc_arc).clone();
                    let yaml_str = match fs::read_to_string(&file_path_clone) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("Failed to read template {}: {}", path_str, e);
                            return;
                        }
                    };

                    let req = tonic::Request::new(valayam_core::rpc::ScanRequest {
                        template_yaml: yaml_str,
                        target_url: target_url.clone(),
                    });

                    match client.scan(req).await {
                        Ok(response) => {
                            let resp = response.into_inner();
                            for finding_json in resp.findings_json {
                                if let Ok(scan_res) = serde_json::from_str::<valayam_core::core::result::ScanResult>(&finding_json) {
                                    let finding = valayam_core::core::scan_result_bridge::scan_result_to_finding(scan_res);
                                    let _ = finding_tx_clone.send(finding).await;
                                }
                            }
                        }
                        Err(e) => tracing::error!("gRPC error for template {}: {}", path_str, e),
                    }
                } else {
                    let template = match VulnerabilityTemplate::load(&file_path_clone) {
                        Ok(t) => Arc::new(t),
                        Err(e) => {
                            tracing::error!("Failed to load Native template {}: {}", path_str, e);
                            return;
                        }
                    };
                    
                    let metrics = exec.execute(&target_url, template).await;
                    for m in metrics {
                        tracing::debug!(
                            plugin = %m.plugin_name,
                            outcome = %m.outcome,
                            duration_ms = m.duration.as_millis() as u64,
                            findings = m.finding_count,
                        );
                    }
                }
            }
        }
    });

    stream.buffer_unordered(concurrency).collect::<Vec<()>>().await;

    // Drop executor and tx to close the channel, allowing consumer to finish
    drop(executor);
    drop(finding_tx);

    registry.shutdown_all().await;

    let findings_count = consumer_handle.await.unwrap_or(0);
    spinner.finish_and_clear();

    if findings_count == 0 {
        println!("\n[+] Scan completed. No vulnerabilities detected.");
    } else {
        println!("\n[+] Scan completed. {} vulnerabilities detected.", findings_count);
        if args.output.is_some() {
            println!("    Results appended to output file.");
        }
    }

    Ok(())
}
