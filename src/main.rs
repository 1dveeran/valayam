mod core;
mod features;
mod network;
mod stealth;
mod template;

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::core::rate_limiter::RateLimiter;

use crate::features::nuclei_compat::executor::NucleiExecutor;
use crate::features::nuclei_compat::parser::NucleiTemplate;
use crate::network::http::StealthHttpClient;
use crate::template::loader::execute_template;
use crate::template::schema::VulnerabilityTemplate;
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
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
    let http_client = Arc::new(StealthHttpClient::new()?);
    let executor_nuclei = NucleiExecutor::new(Arc::clone(&http_client));

    // Initialize rate limiter if configured
    let rate_limiter = args.rate_limit.map(|rps| {
        println!("[+] Rate limiting enabled: {} requests/second", rps);
        Arc::new(RateLimiter::new(rps))
    });

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
    let mut handles = Vec::new();
    for file_path in template_files {
        let client = Arc::clone(&http_client);
        let exec_nuclei = executor_nuclei.clone();
        let target = args.target.clone();
        let rl = rate_limiter.clone();

        handles.push(tokio::spawn(async move {
            let path_str = file_path.to_string_lossy().to_string();
            
            if is_nuclei {
                let template = match NucleiTemplate::load(&file_path) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("\n[!] Failed to load Nuclei template {}: {}", path_str, e);
                        return None;
                    }
                };
                exec_nuclei.execute_scan(&target, template).await
            } else {
                let template = match VulnerabilityTemplate::load(&file_path) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("\n[!] Failed to load Native template {}: {}", path_str, e);
                        return None;
                    }
                };
                execute_template(&client, &target, template, rl.as_ref().map(|r| r.as_ref())).await
            }
      }));
    }

    let results = futures::future::join_all(handles).await;
    spinner.finish_and_clear();

    // 4. Process Results
    let mut findings_count = 0;
    for res in results {
        if let Ok(Some(result)) = res {
            findings_count += 1;
            println!("\n[🚨 VULNERABILITY DETECTED]");
            println!(" ├─ Target:   {}", result.target);
            println!(
                " ├─ Template: {} ({})",
                result.template_name, result.template_id
            );
            println!(" ├─ Severity: {}", result.template_severity);
            println!(" └─ Payload:  {}", result.payload);

            if let Some(ref output_path) = args.output {
                if let Ok(mut file) = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(output_path)
                {
                    if let Ok(json_string) = serde_json::to_string(&result) {
                        let _ = writeln!(file, "{}", json_string);
                    }
                }
            }
        }
    }

    if findings_count == 0 {
        println!("\n[+] Scan completed. No vulnerabilities detected.");
    } else {
        println!(
            "\n[+] Scan completed. {} vulnerabilities detected.",
            findings_count
        );
        if args.output.is_some() {
            println!("    Results written to output file.");
        }
    }

    Ok(())
}
