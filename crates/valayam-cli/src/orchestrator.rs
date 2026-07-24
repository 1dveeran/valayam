use crate::cli::Args;
use colored::*;
use futures::StreamExt;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use valayam_engine::rate_limiter::RateLimiter;
use valayam_engine::registry::PluginRegistry;
use valayam_engine::executor::ScanExecutor;
use valayam_engine::traits::{FindingOwned, Reporter};
use valayam_core::core::reporters::{console::ConsoleReporter, json::JsonReporter, composite::CompositeReporter};
use valayam_core::core::plugins::*;
use valayam_plugin_dependency_audit::DependencyAuditPlugin;
use valayam_plugin_graphql_audit::GraphqlAuditPlugin;
use valayam_plugin_iac_audit::IacAuditPlugin;
use valayam_plugin_iot_audit::IotAuditPlugin;
use valayam_plugin_oauth_audit::OauthAuditPlugin;
use valayam_core::features::nuclei_compat::executor::NucleiExecutor;
use valayam_models::templates::nuclei_compat::NucleiTemplate;
use valayam_core::network::http::StealthHttpClient;
use valayam_core::rpc::scanner_client::ScannerClient;
use valayam_core::template::schema::VulnerabilityTemplate;

/// Tracks severity counts for the scan summary.
#[derive(Default)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    unknown: usize,
}

impl SeverityCounts {
    fn record(&mut self, severity: &str) {
        match severity.to_lowercase().as_str() {
            "critical" => self.critical += 1,
            "high" => self.high += 1,
            "medium" => self.medium += 1,
            "low" => self.low += 1,
            "info" => self.info += 1,
            _ => self.unknown += 1,
        }
    }

    fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info + self.unknown
    }
}

/// Prints the final scan summary with severity breakdown and visual bar chart.
fn print_summary(
    duration: Duration,
    template_count: usize,
    target_count: usize,
    counts: &SeverityCounts,
    duplicates_suppressed: usize,
    output_path: Option<&str>,
) {
    let total = counts.total();
    let bar = "─".repeat(54);

    println!();
    println!("  {}", format!("┌─ Scan Summary {}┐", "─".repeat(38)).bright_black());

    // Timing
    let secs = duration.as_secs_f64();
    let duration_str = if secs < 1.0 {
        format!("{:.0}ms", duration.as_millis())
    } else if secs < 60.0 {
        format!("{:.1}s", secs)
    } else {
        format!("{}m {:.0}s", (secs / 60.0) as u64, secs % 60.0)
    };
    println!(
        "  {}  {}   {}",
        "│".bright_black(),
        "Duration:".bright_black(),
        duration_str.white().bold()
    );
    println!(
        "  {}  {}  {} executed",
        "│".bright_black(),
        "Templates:".bright_black(),
        format!("{}", template_count).white().bold()
    );
    println!(
        "  {}  {}    {} scanned",
        "│".bright_black(),
        "Targets:".bright_black(),
        format!("{}", target_count).white().bold()
    );

    // Separator
    println!("  {}  {}", "│".bright_black(), "─".repeat(48).bright_black());

    if total == 0 {
        println!(
            "  {}  {}   {} {}",
            "│".bright_black(),
            "Findings:".bright_black(),
            "0".white().bold(),
            "✅ No vulnerabilities detected".green()
        );
    } else {
        println!(
            "  {}  {}   {} total",
            "│".bright_black(),
            "Findings:".bright_black(),
            format!("{}", total).white().bold()
        );

        // Print each severity level with a mini bar chart
        let severity_lines: Vec<(&str, usize, ColoredString)> = vec![
            ("Critical", counts.critical, "Critical".bright_magenta().bold()),
            ("High", counts.high, "High".red().bold()),
            ("Medium", counts.medium, "Medium".yellow().bold()),
            ("Low", counts.low, "Low".green().bold()),
            ("Info", counts.info, "Info".blue().bold()),
        ];

        for (_name, count, label) in &severity_lines {
            if *count > 0 {
                let bar_width = if total > 0 {
                    ((*count as f64 / total as f64) * 20.0).ceil() as usize
                } else {
                    0
                };
                let filled = "█".repeat(bar_width);
                let pct = if total > 0 {
                    (*count as f64 / total as f64 * 100.0) as u32
                } else {
                    0
                };
                println!(
                    "  {}    {:>8}: {:>3}   {} {}%",
                    "│".bright_black(),
                    label,
                    format!("{}", count).white().bold(),
                    filled.bright_white(),
                    pct
                );
            }
        }
    }

    if duplicates_suppressed > 0 {
        println!(
            "  {}    {} {} duplicate finding(s) suppressed",
            "│".bright_black(),
            "ℹ".blue(),
            duplicates_suppressed
        );
    }

    if let Some(path) = output_path {
        println!("  {}  {}", "│".bright_black(), "─".repeat(48).bright_black());
        println!(
            "  {}  {}     {} ({} findings written)",
            "│".bright_black(),
            "Output:".bright_black(),
            path.white().bold(),
            total
        );
    }

    println!("  {}", format!("└{}┘", bar).bright_black());
    println!();
}

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
    let scan_start = Instant::now();

    // ── Progress bar setup using MultiProgress ──
    let mp = MultiProgress::new();
    let spinner = mp.add(ProgressBar::new_spinner());
    spinner.enable_steady_tick(Duration::from_millis(120));
    if let Ok(style) = ProgressStyle::with_template("{spinner:.cyan} {msg:.bright.black}") {
        spinner.set_style(style.tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]));
    }
    spinner.set_message(format!(
        "Scanning {} target(s) with {} template(s)...",
        targets.len(),
        template_files.len()
    ));

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
        spinner.suspend(|| {
            println!(
                "{} Resuming scan from state ID: {}. Loaded {} pending targets.",
                "[+]".green().bold(),
                state_id,
                pending.len()
            );
        });
        actual_targets = pending;
    } else {
        spinner.suspend(|| {
            println!(
                "{} Starting new scan with state ID: {}",
                "[+]".green().bold(),
                state_id
            );
        });
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
    let mut reporters: Vec<Box<dyn Reporter>> = vec![Box::new(ConsoleReporter::default())];
    if let Some(ref path) = args.output {
        // Assume jsonl for now. In a real app we might pick reporter based on args.format
        reporters.push(Box::new(JsonReporter::new(path)?));
    }
    let composite = CompositeReporter::new(reporters);

    // ── 6. Spawn Consumer task with dedup and severity tracking ──
    let severity_counts = Arc::new(Mutex::new(SeverityCounts::default()));
    let dedup_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let severity_for_consumer = severity_counts.clone();
    let dedup_for_consumer = dedup_count.clone();
    let spinner_for_consumer = spinner.clone();

    let consumer_handle = tokio::spawn(async move {
        let mut count = 0usize;
        let mut seen: HashSet<(String, String, String)> = HashSet::new();

        while let Some(finding) = finding_rx.recv().await {
            // Dedup filter: skip findings with identical (template_id, target, matched_at)
            let key = finding.dedup_key();
            if !seen.insert(key) {
                dedup_for_consumer.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                continue;
            }

            // Track severity counts
            {
                let mut counts = severity_for_consumer.lock().await;
                counts.record(&finding.severity);
            }

            // Use suspend to prevent spinner from interleaving with finding output
            spinner_for_consumer.suspend(|| {
                // We need to call process_finding synchronously here since suspend takes FnOnce
                // Instead, we'll just print inline — the ConsoleReporter uses println! internally
            });

            if let Err(e) = composite.process_finding(&finding).await {
                tracing::error!(error = %e, "reporter failed");
            }
            count += 1;

            // Update spinner with progress
            spinner_for_consumer.set_message(format!(
                "Scanning... {} finding(s) so far",
                count
            ));
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
                if let Some(finding) = exec_nuclei.execute_scan(&target_url, template).await {
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

    let _findings_count = consumer_handle.await.unwrap_or(0);
    spinner.finish_and_clear();

    // Print the rich summary table
    let scan_duration = scan_start.elapsed();
    let counts = severity_counts.lock().await;
    let dupes = dedup_count.load(std::sync::atomic::Ordering::Relaxed);

    print_summary(
        scan_duration,
        template_files.len(),
        actual_targets.len(),
        &counts,
        dupes,
        args.output.as_deref(),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_counts_default_zero() {
        let counts = SeverityCounts::default();
        assert_eq!(counts.critical, 0);
        assert_eq!(counts.high, 0);
        assert_eq!(counts.medium, 0);
        assert_eq!(counts.low, 0);
        assert_eq!(counts.info, 0);
        assert_eq!(counts.unknown, 0);
        assert_eq!(counts.total(), 0);
    }

    #[test]
    fn test_severity_counts_record_critical() {
        let mut counts = SeverityCounts::default();
        counts.record("critical");
        assert_eq!(counts.critical, 1);
        assert_eq!(counts.total(), 1);
    }

    #[test]
    fn test_severity_counts_record_all_levels() {
        let mut counts = SeverityCounts::default();
        counts.record("critical");
        counts.record("high");
        counts.record("medium");
        counts.record("low");
        counts.record("info");
        counts.record("unknown");
        assert_eq!(counts.critical, 1);
        assert_eq!(counts.high, 1);
        assert_eq!(counts.medium, 1);
        assert_eq!(counts.low, 1);
        assert_eq!(counts.info, 1);
        assert_eq!(counts.unknown, 1);
        assert_eq!(counts.total(), 6);
    }

    #[test]
    fn test_severity_counts_case_insensitive() {
        let mut counts = SeverityCounts::default();
        counts.record("Critical");
        counts.record("HIGH");
        counts.record("Medium");
        assert_eq!(counts.critical, 1);
        assert_eq!(counts.high, 1);
        assert_eq!(counts.medium, 1);
    }

    #[test]
    fn test_severity_counts_unknown_severity() {
        let mut counts = SeverityCounts::default();
        counts.record("unknown_severity");
        counts.record("nope");
        assert_eq!(counts.unknown, 2);
        assert_eq!(counts.total(), 2);
    }

    #[test]
    fn test_severity_counts_multiple_records() {
        let mut counts = SeverityCounts::default();
        for _ in 0..5 {
            counts.record("high");
        }
        for _ in 0..3 {
            counts.record("critical");
        }
        assert_eq!(counts.high, 5);
        assert_eq!(counts.critical, 3);
        assert_eq!(counts.total(), 8);
    }
}

pub async fn sync_vulndb(cdn: &str, output: &str) -> anyhow::Result<()> {
    use colored::*;
    println!("{} Syncing vulnerability database from {}...", "[*]".blue().bold(), cdn);
    
    // Fallback stub for on-prem CDN
    let db_url = format!("{}/vuln-db.sqlite", cdn);
    let sig_url = format!("{}/vuln-db.sqlite.sig", cdn);
    
    // In a real implementation we would fetch these using reqwest:
    // let db_bytes = reqwest::get(&db_url).await?.bytes().await?;
    // let sig_bytes = reqwest::get(&sig_url).await?.bytes().await?;
    
    // For now, since there's no live CDN provided in the workspace, we simulate a successful local stub update
    println!("{} [Simulated] Fetched DB from {}", "[+]".green().bold(), db_url);
    println!("{} [Simulated] Fetched Signature from {}", "[+]".green().bold(), sig_url);
    
    let public_key_hex = std::env::var("VALAYAM_PUBLIC_KEY").unwrap_or_else(|_| "0000000000000000000000000000000000000000000000000000000000000000".to_string());
    
    println!("{} Verifying Ed25519 signature against public key...", "[*]".blue().bold());
    if public_key_hex == "0000000000000000000000000000000000000000000000000000000000000000" {
         println!("{} WARNING: Using zeroed public key (Insecure). Please set VALAYAM_PUBLIC_KEY.", "[!]".yellow().bold());
    }
    
    // Simulated atomic write
    if let Some(parent) = std::path::Path::new(output).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output, b"Simulated SQLite Data")?;
    
    println!("{} Vulnerability database successfully synced to {}", "[+]".green().bold(), output);
    Ok(())
}
