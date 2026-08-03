mod agent;
mod agent_config;
mod cli;
mod orchestrator;
pub mod config;
pub mod notifications;
pub mod reporting;
pub mod state;
pub mod plugin_cli;
mod setup;
mod tracing_init;

use clap::Parser;
use colored::*;
use std::path::Path;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::agent::start_agent;

use setup::*;
use valayam_engine::rate_limiter::RateLimiter;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();
    let config = config::CliConfig::from_env();
    print_banner();
    
    // --- Telemetry setup (console + OTLP + optional file) ---
    let console_level_str = config.valayam_log.clone()
        .unwrap_or_else(|| {
            if args.log_level.eq_ignore_ascii_case("info") {
                "error".to_string()
            } else {
                args.log_level.clone()
            }
        });
    let otlp_endpoint = config.otel_exporter_otlp_endpoint.clone()
        .unwrap_or_else(|| "http://localhost:4317".to_string());
    let _telemetry = tracing_init::init_telemetry(
        &console_level_str,
        &otlp_endpoint,
        args.log_file.as_deref().map(Path::new),
    );

    // Handle plugin subcommands — early return
    if let Some(cli::Commands::Plugin { action }) = &args.command {
        return handle_plugin_command(action).await;
    }
    // Handle vuln DB sync — early return
    if let Some(cli::Commands::SyncVulndb { cdn, output }) = &args.command {
        if let Err(e) = crate::orchestrator::sync_vulndb(cdn, output).await {
            tracing::error!("Failed to sync vulnerability database: {}", e);
        }
        return Ok(());
    }
    // Handle control subcommand — early return
    if let Some(cli::Commands::Control { action, scan_id, port }) = &args.command {
        return handle_control_command(action, scan_id, port).await;
    }
    // Handle agent subcommand — early return (worker polling loop)
    if let Some(cli::Commands::Agent { platform_url, worker_id, poll_interval_secs, heartbeat_interval_secs, capabilities }) = &args.command {
        let cfg = agent_config::AgentConfig {
            platform_url: platform_url.clone(),
            worker_id: worker_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            poll_interval_secs: *poll_interval_secs,
            heartbeat_interval_secs: *heartbeat_interval_secs,
            capabilities: capabilities.split(',').map(|s| s.trim().to_string()).collect(),
            job_secret: std::env::var("PLATFORM_JOB_SECRET").unwrap_or_default(),
        };
        let cancel = CancellationToken::new();
        return start_agent(cfg, cancel).await;
    }

    // ── Template path resolution ──────────────────────────────────────────
    let (template_path, is_nuclei) = resolve_template(&args);
    ensure_demo_template(&template_path);

    // ── Scan state channels ────────────────────────────────────────────────
    let (state_tx, state_rx) = tokio::sync::watch::channel(valayam_engine::scan_state::ScanState::Running);
    let cancel_token = CancellationToken::new();

    // ── TLS config + Telemetry server ──────────────────────────────────────
    let tls_config = load_tls_config(args.tls_cert.as_deref(), args.tls_key.as_deref(), args.tls_ca.as_deref());
    spawn_telemetry_server(args.control_port, tls_config.clone(), state_tx.clone(), cancel_token.clone());

    // ── HTTP client + Proxy ────────────────────────────────────────────────
    let proxy_rotator = init_proxy_rotator(args.proxy_file.as_deref());
    let http_client = init_http_client(&proxy_rotator, args.random_agent, args.allow_internal)?;

    if args.waf_detect {
        println!("  - WAF detection moved to Wasm plugin");
    }
    if let Some(port) = args.mitm_proxy {
        valayam_core::features::ui_proxy::mitm::start_proxy(port, Arc::clone(&http_client)).await;
        return Ok(());
    }

    // ── Rate limiter ───────────────────────────────────────────────────────
    let rate_limiter = args.rate_limit.map(|rps| {
        println!("{} Rate limiting enabled: {} requests/second", "[+]".green().bold(), rps);
        Arc::new(RateLimiter::new_simple(rps))
    });

    // ── gRPC worker client ─────────────────────────────────────────────────
    let grpc_client = connect_worker(args.worker.as_deref()).await;

    // ── Template discovery ─────────────────────────────────────────────────
    let template_files = discover_templates(&template_path);
    if template_files.is_empty() {
        println!("{} No valid YAML templates found in {}", "[!]".yellow().bold(), template_path);
        return Ok(());
    }

    // ── Print scan config ──────────────────────────────────────────────────
    let engine_name = if is_nuclei { "Nuclei" } else { "Native" };
    print_scan_config(
        &args.target,
        template_files.len(),
        engine_name,
        args.concurrency,
        args.rate_limit,
        args.output.as_deref(),
    );

    // ── Crawler ────────────────────────────────────────────────────────────
    let mut targets = vec![args.target.clone()];
    if args.crawl {
        let discovered = run_crawler(
            &args.target,
            http_client.clone(),
            args.crawl_depth,
            rate_limiter.clone(),
            args.crawl_headers.as_deref(),
        ).await;
        targets = discovered;
    }

    // ── Execute scan ───────────────────────────────────────────────────────
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

    // TelemetryGuard is dropped here → flushes + shuts down OTLP tracer provider
    drop(_telemetry);
    Ok(())
}

/// Spawn the telemetry + control gRPC server.
fn spawn_telemetry_server(
    control_port: Option<u16>,
    tls_config: Option<valayam_engine::telemetry_server::TlsConfig>,
    state_tx: tokio::sync::watch::Sender<valayam_engine::scan_state::ScanState>,
    cancel_token: CancellationToken,
) {
    tokio::spawn(async move {
        let port = control_port.unwrap_or(50051);
        let addr = format!("127.0.0.1:{}", port).parse().expect("valid socket addr");
        if let Some(tls) = tls_config {
            if let Err(e) = valayam_engine::telemetry_server::start_telemetry_server_tls(
                addr, Some(state_tx), Some(cancel_token), Some(tls),
            ).await {
                tracing::error!("Telemetry/Control server (TLS) failed: {}", e);
            }
        } else {
            if let Err(e) = valayam_engine::telemetry_server::start_telemetry_server(
                addr, Some(state_tx), Some(cancel_token),
            ).await {
                tracing::error!("Telemetry/Control server failed: {}", e);
            }
        }
    });
}

/// Handle plugin subcommands (package, init, generate-key, install, push, uninstall, list).
async fn handle_plugin_command(action: &cli::PluginCommands) -> anyhow::Result<()> {
    match action {
        cli::PluginCommands::Package { dir, output, sign } => {
            if let Err(e) = crate::plugin_cli::package_plugin(dir, output.as_deref(), sign.as_deref()) {
                tracing::error!("Failed to package plugin: {}", e);
                std::process::exit(1);
            }
        }
        cli::PluginCommands::Init { name, lang, runtime } => {
            if let Err(e) = crate::plugin_cli::init_plugin(name, lang, runtime) {
                tracing::error!("Failed to init plugin: {}", e);
                std::process::exit(1);
            }
        }
        cli::PluginCommands::GenerateKey { output } => {
            if let Err(e) = crate::plugin_cli::generate_key(output) {
                tracing::error!("Failed to generate plugin key: {}", e);
                std::process::exit(1);
            }
        }
        cli::PluginCommands::Install { name, url, pubkey } => {
            if let Err(e) = crate::plugin_cli::install_plugin(name, url, pubkey.as_deref()).await {
                tracing::error!("Failed to install plugin: {}", e);
                std::process::exit(1);
            }
        }
        cli::PluginCommands::Push { file, repo, tag, signature } => {
            if let Err(e) = crate::plugin_cli::push_plugin(file, repo, tag, signature.as_deref()).await {
                tracing::error!("Failed to push plugin to OCI registry: {}", e);
                std::process::exit(1);
            }
        }
        cli::PluginCommands::Uninstall { name } => {
            if let Err(e) = crate::plugin_cli::uninstall_plugin(name) {
                tracing::error!("Failed to uninstall plugin: {}", e);
                std::process::exit(1);
            }
        }
        cli::PluginCommands::List => {
            if let Err(e) = crate::plugin_cli::list_plugins() {
                tracing::error!("Failed to list plugins: {}", e);
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

/// Handle the control subcommand (pause/resume/cancel).
async fn handle_control_command(action: &str, scan_id: &Option<String>, port: &u16) -> anyhow::Result<()> {
    use valayam_engine::rpc::scanner_client::ScannerClient;
    use valayam_engine::rpc::ControlRequest;

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

    match action {
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
    Ok(())
}

/// Connect to a remote gRPC worker node.
async fn connect_worker(worker_url: Option<&str>) -> Option<valayam_core::rpc::scanner_client::ScannerClient<tonic::transport::Channel>> {
    use valayam_core::rpc::scanner_client::ScannerClient;
    match worker_url {
        Some(url) => match ScannerClient::connect(url.to_string()).await {
            Ok(client) => {
                println!("{} Connected to Valayam worker node at {}", "[+]".green().bold(), url);
                Some(client)
            }
            Err(e) => {
                eprintln!("{} Failed to connect to Valayam worker node: {}", "[✗]".red().bold(), e);
                None
            }
        },
        None => None,
    }
}