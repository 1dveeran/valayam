mod cli;
mod orchestrator;
pub mod notifications;
pub mod reporting;
pub mod state;
pub mod plugin_cli;

use clap::Parser;
use colored::*;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use walkdir::WalkDir;
use opentelemetry_otlp::WithExportConfig;

use valayam_engine::rate_limiter::RateLimiter;
// NucleiExecutor moved to Wasm
use valayam_core::network::http::StealthHttpClient;
use valayam_core::stealth::proxy::ProxyRotator;

/// Prints the branded Valayam ASCII banner to stdout.
fn print_banner() {
    let banner = r#"
 ██╗   ██╗ █████╗ ██╗      █████╗ ██╗   ██╗ █████╗ ███╗   ███╗
 ██║   ██║██╔══██╗██║     ██╔══██╗╚██╗ ██╔╝██╔══██╗████╗ ████║
 ██║   ██║███████║██║     ███████║ ╚████╔╝ ███████║██╔████╔██║
 ╚██╗ ██╔╝██╔══██║██║     ██╔══██║  ╚██╔╝  ██╔══██║██║╚██╔╝██║
  ╚████╔╝ ██║  ██║███████╗██║  ██║   ██║   ██║  ██║██║ ╚═╝ ██║
   ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝"#;
    println!("{}", banner.bright_cyan());
    println!(
        "{}",
        "                    Modern Stealth Scanner v0.1.0\n"
            .bright_black()
    );
}

/// Prints a boxed scan configuration summary.
fn print_scan_config(target: &str, template_count: usize, engine: &str, concurrency: usize, rate_limit: Option<u32>, output: Option<&str>) {
    let bar = "─".repeat(54);
    println!("  {}", format!("┌─ Scan Configuration {}┐", "─".repeat(32)).bright_black());
    println!("  {}  {}     {}", "│".bright_black(), "Target:".bright_black(), target.cyan().bold());
    println!("  {}  {}  {} {} {}", "│".bright_black(), "Templates:".bright_black(), format!("{}", template_count).white().bold(), "loaded".bright_black(), format!("({})", engine).bright_black());
    let rate_str = rate_limit.map_or("unlimited".to_string(), |r| format!("{} req/s", r));
    println!("  {}  {}       {} {} {} {}", "│".bright_black(), "Tuning:".bright_black(), "concurrency".bright_black(), format!("{}", concurrency).white(), "│ rate limit".bright_black(), rate_str.white());
    if let Some(out) = output {
        println!("  {}  {}     {} {}", "│".bright_black(), "Output:".bright_black(), "console".white(), format!("+ {}", out).bright_black());
    } else {
        println!("  {}  {}     {}", "│".bright_black(), "Output:".bright_black(), "console".white());
    }
    println!("  {}", format!("└{}┘", bar).bright_black());
    println!();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();
    print_banner();
    
    // Parse log level from string. Default to WARN to keep CLI output clean,
    // unless the user explicitly requested debug or trace.
    let level_str = if args.log_level.eq_ignore_ascii_case("info") {
        "warn"
    } else {
        &args.log_level
    };
    let level = level_str.parse::<tracing::Level>().unwrap_or(tracing::Level::WARN);
    let level_filter = tracing_subscriber::filter::LevelFilter::from_level(level);

    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

    // Console layer (text format)
    let console_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_filter(level_filter);

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
    
    let (template_path, is_nuclei) = if let Some(cli::Commands::Plugin { action }) = &args.command {
        match action {
            cli::PluginCommands::Package { dir, output, sign } => {
                if let Err(e) = crate::plugin_cli::package_plugin(dir, output.as_deref(), sign.as_deref()) {
                    tracing::error!("Failed to package plugin: {}", e);
                    std::process::exit(1);
                }
                return Ok(());
            }
            cli::PluginCommands::Init { name, lang, runtime } => {
                if let Err(e) = crate::plugin_cli::init_plugin(name, lang, runtime) {
                    tracing::error!("Failed to init plugin: {}", e);
                    std::process::exit(1);
                }
                return Ok(());
            }
            cli::PluginCommands::GenerateKey { output } => {
                if let Err(e) = crate::plugin_cli::generate_key(output) {
                    tracing::error!("Failed to generate plugin key: {}", e);
                    std::process::exit(1);
                }
                return Ok(());
            }
            cli::PluginCommands::Install { name, url, pubkey } => {
                if let Err(e) = crate::plugin_cli::install_plugin(name, url, pubkey.as_deref()).await {
                    tracing::error!("Failed to install plugin: {}", e);
                    std::process::exit(1);
                }
                return Ok(());
            }
            cli::PluginCommands::Push { file, repo, tag, signature } => {
                if let Err(e) = crate::plugin_cli::push_plugin(file, repo, tag, signature.as_deref()).await {
                    tracing::error!("Failed to push plugin to OCI registry: {}", e);
                    std::process::exit(1);
                }
                return Ok(());
            }
            cli::PluginCommands::Uninstall { name } => {
                if let Err(e) = crate::plugin_cli::uninstall_plugin(name) {
                    tracing::error!("Failed to uninstall plugin: {}", e);
                    std::process::exit(1);
                }
                return Ok(());
            }
            cli::PluginCommands::List => {
                if let Err(e) = crate::plugin_cli::list_plugins() {
                    tracing::error!("Failed to list plugins: {}", e);
                    std::process::exit(1);
                }
                return Ok(());
            }
        }
    } else if let Some(cli::Commands::SyncVulndb { cdn, output }) = &args.command {
        if let Err(e) = crate::orchestrator::sync_vulndb(cdn, output).await {
            tracing::error!("Failed to sync vulnerability database: {}", e);
            std::process::exit(1);
        }
        return Ok(());
    } else if let Some(cli::Commands::Control { action, scan_id, port }) = &args.command {
        use valayam_engine::plugin_rpc::scanner_client::ScannerClient;
        use valayam_engine::plugin_rpc::ControlRequest;
        
        let url = format!("http://127.0.0.1:{}", port);
        let mut client = match ScannerClient::connect(url.clone()).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to connect to control plane at {}: {}", url, e);
                std::process::exit(1);
            }
        };

        let req = tonic::Request::new(ControlRequest {
            scan_id: scan_id.clone().unwrap_or_default(),
        });

        match action.as_str() {
            "pause" => {
                match client.pause_scan(req).await {
                    Ok(resp) => println!("{} {}", "[+]".green().bold(), resp.into_inner().message),
                    Err(e) => tracing::error!("Failed to pause scan: {}", e),
                }
            }
            "resume" => {
                match client.resume_scan(req).await {
                    Ok(resp) => println!("{} {}", "[+]".green().bold(), resp.into_inner().message),
                    Err(e) => tracing::error!("Failed to resume scan: {}", e),
                }
            }
            "cancel" | "stop" => {
                match client.cancel_scan(req).await {
                    Ok(resp) => println!("{} {}", "[+]".green().bold(), resp.into_inner().message),
                    Err(e) => tracing::error!("Failed to cancel scan: {}", e),
                }
            }
            _ => tracing::error!("Unknown control action '{}'. Valid actions: pause, resume, cancel", action),
        }
        return Ok(());
    } else if let Some(t) = &args.template {
        (t.as_str(), false)
    } else if let Some(n) = &args.nuclei_template {
        (n.as_str(), true)
    } else {
        println!("{} No template flag provided. Defaulting to Native engine with demo template (-t {}).", "[!]".yellow().bold(), default_template);
        (default_template.as_str(), false)
    };

    // --- Developer QoL: Auto-generate a demo template if it doesn't exist ---
    if !is_nuclei && !Path::new(template_path).exists() {
        println!(
            "{} Native template not found at '{}'. Generating demo template...",
            "[!]".yellow().bold(),
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
        println!("{} Demo template created successfully.\n", "[+]".green().bold());
    }

    let (state_tx, state_rx) = tokio::sync::watch::channel(valayam_engine::executor::ScanState::Running);
    let cancel_token = tokio_util::sync::CancellationToken::new();
    let state_tx_clone = state_tx.clone();
    let cancel_token_clone = cancel_token.clone();

    // Start Telemetry & Control Server in background
    tokio::spawn(async move {
        // If args.control_port is set, we could use that, otherwise default to 50051.
        let port = args.control_port.unwrap_or(50051);
        let addr = format!("127.0.0.1:{}", port).parse().unwrap();
        if let Err(e) = valayam_engine::telemetry_server::start_telemetry_server(addr, Some(state_tx_clone), Some(cancel_token_clone)).await {
            tracing::error!("Telemetry/Control server failed: {}", e);
        }
    });

    // 1. Initialize Stealth Core
    let proxy_rotator = if let Some(path) = &args.proxy_file {
        match ProxyRotator::load_from_file(path) {
            Ok(rotator) => {
                println!("{} Loaded {} proxies from {}", "[+]".green().bold(), rotator.len(), path);
                Some(rotator)
            }
            Err(e) => {
                eprintln!("{} Failed to load proxies: {}", "[✗]".red().bold(), e);
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

    if args.waf_detect {
        println!("  - WAF detection moved to Wasm plugin");
    }

    if let Some(port) = args.mitm_proxy {
        valayam_core::features::ui_proxy::mitm::start_proxy(port, Arc::clone(&http_client)).await;
        return Ok(());
    }

    // Initialize rate limiter if configured
    let rate_limiter = args.rate_limit.map(|rps| {
        println!("{} Rate limiting enabled: {} requests/second", "[+]".green().bold(), rps);
        Arc::new(RateLimiter::new_simple(rps))
    });

    // 1.5 Initialize gRPC Client if requested
    let mut grpc_client = None;
    if let Some(ref worker_url) = args.worker {
        use valayam_core::rpc::scanner_client::ScannerClient;
        match ScannerClient::connect(worker_url.clone()).await {
            Ok(client) => {
                println!("{} Connected to Valayam worker node at {}", "[+]".green().bold(), worker_url);
                grpc_client = Some(client);
            }
            Err(e) => {
                eprintln!("{} Failed to connect to Valayam worker node: {}", "[✗]".red().bold(), e);
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
        println!("{} No valid YAML templates found in {}", "[!]".yellow().bold(), template_path);
        return Ok(());
    }

    let engine_name = if is_nuclei { "Nuclei" } else { "Native" };
    print_scan_config(
        &args.target,
        template_files.len(),
        engine_name,
        args.concurrency,
        args.rate_limit,
        args.output.as_deref(),
    );

    // 2.5 Run Web Crawler if requested to build target URLs list
    let mut targets = vec![args.target.clone()];
    if args.crawl {
        println!("{} Starting Web Crawler discovery on {}...", "[*]".blue().bold(), args.target);
        
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
                println!("{} Crawler discovered {} page(s) on target domain.", "[+]".green().bold(), discovered.len());
                if !discovered.is_empty() {
                    targets = discovered.into_iter().collect();
                }
            }
            Err(e) => {
                eprintln!("{} Failed to initialize crawler: {}", "[✗]".red().bold(), e);
            }
        }
    }
    orchestrator::run_scan(
        args,
        template_files,
        is_nuclei,
        targets,
        http_client,
        rate_limiter,
        grpc_client,
        Some(state_rx),
        cancel_token,
    ).await?;

    opentelemetry::global::shutdown_tracer_provider();
    Ok(())
}
