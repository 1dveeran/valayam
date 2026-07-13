use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use valayam_core::core::rate_limiter::RateLimiter;

use valayam_core::features::nuclei_compat::executor::NucleiExecutor;
use valayam_core::features::nuclei_compat::parser::NucleiTemplate;
use valayam_core::network::http::StealthHttpClient;
use valayam_core::stealth::proxy::ProxyRotator;
use valayam_core::template::loader::execute_template;
use valayam_core::template::schema::VulnerabilityTemplate;
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(
    name = "valayam",
    version = "0.1.0",
    about = "Modern Stealth Scanner Core\n\nA high-performance, template-driven scanner supporting HTTP requests,\nTCP port scanning, and embedded Rhai scripting for multi-step workflows.",
    after_help = "\x1b[1;36mEXAMPLES:\x1b[0m
  \x1b[1mBasic HTTP template scan:\x1b[0m
    valayam -u https://target.com -t ./templates_repo/demo-template.yaml

  \x1b[1mBatch template execution (runs all .yaml files in directory concurrently):\x1b[0m
    valayam -u https://target.com -t ./templates_repo/

  \x1b[1mRhai script template (multi-step chain):\x1b[0m
    valayam -u https://target.com -t ./templates_repo/script-demo.yaml

  \x1b[1mSave findings to JSON:\x1b[0m
    valayam -u https://target.com -t ./templates_repo/ -o results.json

\x1b[1;36mTEMPLATE TYPES:\x1b[0m
  Templates are YAML files that can contain any combination of:
    \x1b[33mrequests:\x1b[0m   HTTP request rules with regex/status matchers
    \x1b[33mnetwork:\x1b[0m    TCP port scanning rules
    \x1b[33mscripts:\x1b[0m    Embedded Rhai scripts for multi-step logic

  A single template can mix all three. The engine executes them in order:
  HTTP → Network → Scripts. No separate flag is needed for scripts."
)]
struct Args {
    #[arg(short = 'u', long, default_value = "https://httpbin.org", help = "Target Base URL")]
    target: String,

    #[arg(
        short = 't',
        long,
        help = "Path to Native YAML template file/dir (HTTP/TCP/Rhai)",
        conflicts_with = "nuclei_template"
    )]
    template: Option<String>,

    #[arg(
        short = 'n',
        long,
        help = "Path to Nuclei YAML template file/dir (Isolated execution engine)",
        conflicts_with = "template"
    )]
    nuclei_template: Option<String>,

    #[arg(short = 'o', long, help = "Path to write JSON output to")]
    output: Option<String>,

    #[arg(short = 'r', long, help = "Max requests per second (global rate limit)")]
    rate_limit: Option<u32>,

    #[arg(long, help = "Rotate User-Agent header randomly per request")]
    random_agent: bool,

    #[arg(long, help = "Path to proxy list file (one proxy per line)")]
    proxy_file: Option<String>,

    #[arg(short = 'l', long, default_value = "info", help = "Log level (trace, debug, info, warn, error)")]
    log_level: String,

    #[arg(short = 'f', long, help = "Path to output verbose logs to a JSON file")]
    log_file: Option<String>,

    #[arg(long, help = "URI of a Valayam gRPC worker node (e.g. http://127.0.0.1:50051)")]
    worker: Option<String>,

    #[arg(long, help = "Crawl the target URL first to discover pages")]
    crawl: bool,

    #[arg(long, default_value = "3", help = "Maximum depth for crawler")]
    crawl_depth: usize,

    #[arg(long, help = "Custom headers for crawler requests (format: Key:Value,Key2:Value2)")]
    crawl_headers: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    
    // Parse log level from string
    let level = args.log_level.parse::<tracing::Level>().unwrap_or(tracing::Level::INFO);
    let level_filter = tracing_subscriber::filter::LevelFilter::from_level(level);

    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

    // Console layer (text format)
    let console_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_filter(level_filter);

    // Optional File layer (JSON format)
    if let Some(log_path) = &args.log_file {
        let file = std::fs::File::create(log_path).expect("Failed to create log file");
        let (non_blocking, _guard) = tracing_appender::non_blocking(file);
        
        let file_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(non_blocking)
            .with_filter(level_filter);

        tracing_subscriber::registry()
            .with(console_layer)
            .with(file_layer)
            .init();
            
        // We need to keep _guard alive in a real app, but for this CLI we can let it leak 
        // or just accept it'll flush on drop. Since we use `tokio::main`, standard `std::mem::forget` 
        // or leaking is okay, but `tracing_appender::non_blocking` docs recommend keeping the guard.
        // For simplicity, we'll leak it so it stays alive for the duration of the program.
        std::mem::forget(_guard);
    } else {
        tracing_subscriber::registry()
            .with(console_layer)
            .init();
    }

    // Extract template path, defaulting to a generated native demo template if neither flag is provided
    let default_template = "./templates_repo/demo-template.yaml".to_string();
    
    let (template_path, is_nuclei) = if let Some(t) = &args.template {
        (t.as_str(), false)
    } else if let Some(n) = &args.nuclei_template {
        (n.as_str(), true)
    } else {
        println!("[!] No template flag provided. Defaulting to Native engine with demo template (-t {}).", default_template);
        (default_template.as_str(), false)
    };

    // --- Developer QoL: Auto-generate a demo template if it doesn't exist ---
    if !is_nuclei && !Path::new(template_path).exists() {
        println!(
            "[!] Native template not found at '{}'. Generating demo template...",
            template_path
        );

        // Ensure the directory exists
        if let Some(parent_dir) = Path::new(template_path).parent() {
            fs::create_dir_all(parent_dir)?;
        }

        let demo_yaml = r#"
id: basic-info-disclosure
info:
  name: "Basic Information Disclosure / SSRF Test"
  severity: "Medium"
  description: "Detects if the target reflects sensitive HTTP headers or payloads."
requests:
  - method: "GET"
    path: "/get?test_param=valayam_engine"
    headers:
      X-Scanner-Test: "true"
    matchers:
      - type: "regex"
        part: "body"
        regex:
          - "valayam_engine"
      - type: "status"
        part: "status"
        status:
          - 200
network:
  - host: "{{Hostname}}"
    ports:
      - "80"
      - "443"
      - "8080"
"#;
        fs::write(template_path, demo_yaml.trim())?;
        println!("[+] Demo template created successfully.\n");
    }

    // 1. Initialize Stealth Core
    let proxy_rotator = if let Some(path) = &args.proxy_file {
        match ProxyRotator::load_from_file(path) {
            Ok(rotator) => {
                println!("[+] Loaded {} proxies from {}", rotator.len(), path);
                Some(rotator)
            }
            Err(e) => {
                eprintln!("[!] Failed to load proxies: {}", e);
                None
            }
        }
    } else {
        None
    };

    let http_client = Arc::new(StealthHttpClient::new(args.random_agent, proxy_rotator)?);
    let executor_nuclei = NucleiExecutor::new(Arc::clone(&http_client));

    // Initialize rate limiter if configured
    let rate_limiter = args.rate_limit.map(|rps| {
        println!("[+] Rate limiting enabled: {} requests/second", rps);
        Arc::new(RateLimiter::new(rps))
    });

    // 1.5 Initialize gRPC Client if requested
    let mut grpc_client = None;
    if let Some(ref worker_url) = args.worker {
        use valayam_core::rpc::scanner_client::ScannerClient;
        match ScannerClient::connect(worker_url.clone()).await {
            Ok(client) => {
                println!("[+] Connected to Valayam worker node at {}", worker_url);
                grpc_client = Some(client);
            }
            Err(e) => {
                eprintln!("[!] Failed to connect to Valayam worker node: {}", e);
                return Ok(());
            }
        }
    }

    // 2. Discover Templates
    let mut template_files = Vec::new();
    let p = Path::new(template_path);
    if p.is_dir() {
        for entry in WalkDir::new(p).into_iter().filter_map(|e| e.ok()) {
            if entry.path().is_file() {
                if let Some(ext) = entry.path().extension() {
                    if ext == "yaml" || ext == "yml" {
                        template_files.push(entry.path().to_path_buf());
                    }
                }
            }
        }
    } else if p.is_file() {
        template_files.push(p.to_path_buf());
    }

    if template_files.is_empty() {
        println!("[!] No valid YAML templates found in {}", template_path);
        return Ok(());
    }

    println!(
        "[+] Found {} template(s). Starting concurrent {} scan...",
        template_files.len(),
        if is_nuclei { "Nuclei" } else { "Native" }
    );

    let spinner = ProgressBar::new_spinner();
    spinner.enable_steady_tick(Duration::from_millis(120));
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.blue} {msg}")?
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    spinner.set_message(format!("Scanning {}...", args.target));

    // 3. Dispatch Tasks Concurrently
    let (tx, mut rx) = tokio::sync::mpsc::channel::<valayam_core::core::result::ScanResult>(100);
    let output_path = args.output.clone();
    
    // Spawn dedicated writer task
    let writer_task = tokio::spawn(async move {
        let mut findings_count = 0;
        let mut file_opt = output_path.as_ref().and_then(|path| {
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()
        });

        while let Some(result) = rx.recv().await {
            findings_count += 1;
            println!("\n[🚨 VULNERABILITY DETECTED]");
            println!(" ├─ Target:   {}", result.target);
            println!(" ├─ Template: {} ({})", result.template_name, result.template_id);
            println!(" ├─ Severity: {}", result.template_severity);
            println!(" └─ Payload:  {}", result.payload);

            if let Some(file) = &mut file_opt {
                if let Ok(json_string) = serde_json::to_string(&result) {
                    let _ = writeln!(file, "{}", json_string);
                }
            }
        }
        findings_count
    });

    // 2.5 Run Web Crawler if requested to build target URLs list
    let mut targets = vec![args.target.clone()];
    if args.crawl {
        println!("[*] Starting Web Crawler discovery on {}...", args.target);
        
        let crawl_hdrs = args.crawl_headers.as_ref().map(|s| {
            let mut map = std::collections::HashMap::new();
            for kv in s.split(',') {
                let mut parts = kv.splitn(2, ':');
                if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                    map.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
            map
        });

        use valayam_core::features::crawler::Crawler;
        let crawler = Crawler::new(
            Arc::clone(&http_client),
            &args.target,
            args.crawl_depth,
            rate_limiter.clone(),
            crawl_hdrs,
        );
        match crawler {
            Ok(c) => {
                let discovered = c.run().await;
                println!("[+] Crawler discovered {} page(s) on target domain.", discovered.len());
                if !discovered.is_empty() {
                    targets = discovered.into_iter().collect();
                }
            }
            Err(e) => {
                eprintln!("[!] Failed to initialize crawler: {}", e);
            }
        }
    }

    let mut handles = Vec::new();
    for target in targets {
        for file_path in &template_files {
            let client = Arc::clone(&http_client);
            let exec_nuclei = executor_nuclei.clone();
            let target_url = target.clone();
            let rl = rate_limiter.clone();
            let tx = tx.clone();
            let grpc_client_clone = grpc_client.clone();
            let file_path_clone = file_path.clone();

            handles.push(tokio::spawn(async move {
                let path_str = file_path_clone.to_string_lossy().to_string();
                
                let result = if is_nuclei {
                    let template = match NucleiTemplate::load(&file_path_clone) {
                        Ok(t) => t,
                        Err(e) => {
                            eprintln!("\n[!] Failed to load Nuclei template {}: {}", path_str, e);
                            return;
                        }
                    };
                    exec_nuclei.execute_scan(&target_url, template).await
                } else {
                    if let Some(mut client) = grpc_client_clone {
                        // Remote execution via gRPC
                        let yaml_str = match fs::read_to_string(&file_path_clone) {
                            Ok(s) => s,
                            Err(e) => {
                                eprintln!("\n[!] Failed to read template {}: {}", path_str, e);
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
                                eprintln!("\n[!] gRPC error for template {}: {}", path_str, e);
                                None
                            }
                        }
                    } else {
                        // Local execution
                        let template = match VulnerabilityTemplate::load(&file_path_clone) {
                            Ok(t) => t,
                            Err(e) => {
                                eprintln!("\n[!] Failed to load Native template {}: {}", path_str, e);
                                return;
                            }
                        };
                        execute_template(&client, &target_url, template, rl.as_ref().map(|r| r.as_ref())).await
                    }
                };

                if let Some(finding) = result {
                    let _ = tx.send(finding).await;
                }
            }));
        }
    }

    // Drop the original sender so rx closes when all workers finish
    drop(tx);

    // Wait for all workers to finish
    futures::future::join_all(handles).await;
    
    // Wait for the writer task to finish processing the last messages
    let findings_count = writer_task.await.unwrap_or(0);
    
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
