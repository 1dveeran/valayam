mod cli;
mod orchestrator;
pub mod mitm;
pub mod notifications;
pub mod reporting;
pub mod cert_auth;
pub mod state;

use clap::Parser;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use walkdir::WalkDir;
use opentelemetry_otlp::WithExportConfig;

use valayam_core::core::rate_limiter::RateLimiter;
use valayam_core::features::nuclei_compat::executor::NucleiExecutor;
use valayam_core::network::http::StealthHttpClient;
use valayam_core::stealth::proxy::ProxyRotator;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();
    
    // Parse log level from string
    let level = args.log_level.parse::<tracing::Level>().unwrap_or(tracing::Level::INFO);
    let level_filter = tracing_subscriber::filter::LevelFilter::from_level(level);

    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

    // Console layer (text format)
    let console_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_filter(level_filter.clone());

    // OpenTelemetry pipeline setup
    let otlp_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4317".to_string());
    
    let _tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(otlp_endpoint)
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .expect("Failed to initialize OTLP pipeline");

    // We remove the telemetry layer setup since tracing-subscriber trait bound resolution with tracing-opentelemetry is complex and broken in this setup.
    // An enterprise setup usually puts otel tracer as the global default or carefully types the Registry.

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

    let http_client = Arc::new(StealthHttpClient::new(
        proxy_rotator.is_some(),
        args.random_agent,
        None,
        true,
    )?);
    let executor_nuclei = NucleiExecutor::new(Arc::clone(&http_client));

    if args.waf_detect {
        println!("[*] Starting WAF Detection on {}...", args.target);
        let detections = valayam_core::features::waf_detect::detector::detect_waf(&http_client, &args.target).await;
        if detections.is_empty() {
            println!("[+] No WAF detected. The target appears to be unshielded.");
        } else {
            println!("[!] WAF Detected!");
            for det in detections {
                println!(" ├─ Product:  {}", det.product);
                println!(" └─ Evidence: {}", det.evidence);
            }
        }
        println!();
    }

    if let Some(port) = args.mitm_proxy {
        mitm::start_proxy(port, Arc::clone(&http_client)).await;
        return Ok(());
    }

    // Initialize rate limiter if configured
    let rate_limiter = args.rate_limit.map(|rps| {
        println!("[+] Rate limiting enabled: {} requests/second", rps);
        Arc::new(RateLimiter::new_simple(rps))
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

    orchestrator::run_scan(
        args,
        template_files,
        is_nuclei,
        targets,
        http_client,
        executor_nuclei,
        rate_limiter,
        grpc_client
    ).await?;

    opentelemetry::global::shutdown_tracer_provider();
    Ok(())
}
