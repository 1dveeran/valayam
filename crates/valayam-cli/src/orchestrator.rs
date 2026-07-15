use crate::cli::Args;
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use valayam_core::core::rate_limiter::RateLimiter;
use valayam_core::features::nuclei_compat::executor::NucleiExecutor;
use valayam_core::features::nuclei_compat::parser::NucleiTemplate;
use valayam_core::network::http::StealthHttpClient;
use valayam_core::rpc::scanner_client::ScannerClient;
use valayam_core::template::loader::execute_template;
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

    let (tx, mut rx) = tokio::sync::mpsc::channel::<valayam_core::core::result::ScanResult>(1000);
    let output_path = args.output.clone();
    let format = args.format.to_lowercase();
    let concurrency = args.concurrency;
    let writer_task = tokio::spawn(async move {
        let mut findings = Vec::new();

        while let Some(result) = rx.recv().await {
            println!("\n[🚨 VULNERABILITY DETECTED]");
            println!(" ├─ Target:   {}", result.target); 
            println!(" ├─ Template: {} ({})", result.template_name, result.template_id);
            println!(" ├─ Severity: {}", result.template_severity);
            
            findings.push(result);
        }
        
        if let Some(path) = &output_path {
            match format.as_str() {
                "sarif" => {
                    if let Ok(file) = fs::File::create(path) {
                        let sarif_val = crate::reporting::sarif::generate_sarif(&findings);
                        let _ = serde_json::to_writer_pretty(file, &sarif_val);
                    }
                }
                "pdf" => {
                    let _ = crate::reporting::pdf::generate_pdf(&findings, path);
                }
                _ => { // default to jsonl
                    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
                        for finding in &findings {
                            if let Ok(json_string) = serde_json::to_string(&finding) {
                                let _ = writeln!(file, "{}", json_string);
                            }
                        }
                    }
                }
            }
        }
        
        findings.len()
    });

    let db = crate::state::StateDB::new(".valayam_state").expect("Failed to initialize state DB");
    let state_id = args.resume.unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs().to_string());

    let mut actual_targets = targets.clone();
    if let Some((pending, _completed)) = db.load_state(&state_id).unwrap_or(None) {
        println!("[+] Resuming scan from state ID: {}. Loaded {} pending targets.", state_id, pending.len());
        actual_targets = pending;
    } else {
        println!("[+] Starting new scan with state ID: {}", state_id);
    }

    let mut tasks = Vec::new();
    for target in &actual_targets {
        for file_path in &template_files {
            tasks.push((target.clone(), file_path.clone()));
        }
    }

    let tx_clone = tx.clone();
    let grpc_client_arc = grpc_client.map(Arc::new);
    let rl_ref = rate_limiter.clone();

    // To track pending for shutdown, we could use an Arc<Mutex> but for MVP we will just save the raw list
    let pending_for_shutdown = actual_targets.clone();
    let shutdown_signal = async move {
        if let Ok(_) = tokio::signal::ctrl_c().await {
            tracing::warn!("Received Ctrl+C, saving state {} and shutting down gracefully...", state_id);
            let _ = db.save_state(&state_id, &pending_for_shutdown, &[]);
        }
    };

    let stream = futures::stream::iter(tasks).map(|(target_url, file_path_clone)| {
        let client = Arc::clone(&http_client);
        let exec_nuclei = executor_nuclei.clone();
        let rl = rl_ref.clone();
        let tx = tx_clone.clone();
        let grpc_client_clone = grpc_client_arc.clone();

        async move {
            let path_str = file_path_clone.to_string_lossy().to_string();

            let result = if is_nuclei {
                let template = match NucleiTemplate::load(&file_path_clone) {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::error!("Failed to load Nuclei template {}: {}", path_str, e);
                        return;
                    }
                };
                exec_nuclei.execute_scan(&target_url, template).await
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
                                    let _ = tx.send(scan_res).await;
                                }
                            }
                            None
                        }
                        Err(e) => {
                            tracing::error!("gRPC error for template {}: {}", path_str, e);
                            None
                        }
                    }
                } else {
                    let template = match VulnerabilityTemplate::load(&file_path_clone) {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::error!("Failed to load Native template {}: {}", path_str, e);
                            return;
                        }
                    };
                    execute_template(&client, &target_url, template, rl.as_ref().map(|r| r.as_ref())).await
                }
            };

            if let Some(finding) = result {
                let _ = tx.send(finding).await;
            }
        }
    });

    tokio::select! {
        _ = stream.buffer_unordered(concurrency).collect::<Vec<()>>() => {
            // Completed naturally
        }
        _ = shutdown_signal => {
            println!("\n[!] Scan interrupted by user. Flushing results...");
        }
    }

    drop(tx);
    drop(tx_clone);

    let findings_count = writer_task.await.unwrap_or(0);
    spinner.finish_and_clear();

    if findings_count == 0 {
        println!("\n[+] Scan completed. No vulnerabilities detected.");
    } else {
        println!("\n[+] Scan completed. {} vulnerabilities detected.", findings_count);
        if args.output.is_some() {
            println!("    Results appended to output file in JSONL format.");
        }
    }

    Ok(())
}
