// TODO: Refactor CLI application for Enterprise execution (Phase 4 & 5).
// - Integrate standard Clap subcommands (`scan`, `listen`, `serve`, `crawl`).
// - Implement advanced batch execution logic for directory template scanning.
// - Integrate the AI Autonomous Loop fallback execution.
// - Finalize reporting/ notifications (JSONL, Webhooks, PDF generation).
use clap::Parser;

#[derive(Parser, Debug, Clone)]
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

  \x1b[1mSave findings to JSONL:\x1b[0m
    valayam -u https://target.com -t ./templates_repo/ -o results.jsonl

\x1b[1;36mTEMPLATE TYPES:\x1b[0m
  Templates are YAML files that can contain any combination of:
    \x1b[33mrequests:\x1b[0m   HTTP request rules with regex/status matchers
    \x1b[33mnetwork:\x1b[0m    TCP port scanning rules
    \x1b[33mscripts:\x1b[0m    Embedded Rhai scripts for multi-step logic

  A single template can mix all three. The engine executes them in order:
  HTTP → Network → Scripts. No separate flag is needed for scripts."
)]
pub struct Args {
    #[arg(short = 'u', long, default_value = "https://httpbin.org", help = "Target Base URL")]
    pub target: String,

    #[arg(
        short = 't',
        long,
        help = "Path to Native YAML template file/dir (HTTP/TCP/Rhai)",
        conflicts_with = "nuclei_template"
    )]
    pub template: Option<String>,

    #[arg(
        short = 'n',
        long,
        help = "Path to Nuclei YAML template file/dir (Isolated execution engine)",
        conflicts_with = "template"
    )]
    pub nuclei_template: Option<String>,

    #[arg(short = 'o', long, help = "Path to write output to")]
    pub output: Option<String>,

    #[arg(long, default_value = "json", help = "Output format (json, sarif, pdf)")]
    pub format: String,

    #[arg(short = 'r', long, help = "Max requests per second (global rate limit)")]
    pub rate_limit: Option<u32>,

    #[arg(long, default_value = "500", help = "Max concurrent template executions")]
    pub concurrency: usize,

    #[arg(long, help = "Rotate User-Agent header randomly per request")]
    pub random_agent: bool,

    #[arg(long, help = "Path to proxy list file (one proxy per line)")]
    pub proxy_file: Option<String>,

    #[arg(short = 'l', long, default_value = "info", help = "Log level (trace, debug, info, warn, error)")]
    pub log_level: String,

    #[arg(short = 'f', long, help = "Path to output verbose logs to a JSON file")]
    pub log_file: Option<String>,

    #[arg(long, help = "URI of a Valayam gRPC worker node (e.g. http://127.0.0.1:50051)")]
    pub worker: Option<String>,

    #[arg(long, help = "Crawl the target URL first to discover pages")]
    pub crawl: bool,

    #[arg(long, default_value = "3", help = "Maximum depth for crawler")]
    pub crawl_depth: usize,

    #[arg(long, help = "Custom headers for crawler requests (format: Key:Value,Key2:Value2)")]
    pub crawl_headers: Option<String>,

    #[arg(long, help = "Detect and fingerprint Web Application Firewalls (WAF) before scanning")]
    pub waf_detect: bool,

    #[arg(long, help = "Start a local MITM proxy on the specified port to capture traffic and generate templates")]
    pub mitm_proxy: Option<u16>,

    #[arg(long, help = "Resume a previously interrupted scan using its state ID")]
    pub resume: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum Commands {
    /// Plugin management utilities
    Plugin {
        #[command(subcommand)]
        action: PluginCommands,
    },
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum PluginCommands {
    /// Package a plugin directory into a .vpa archive
    Package {
        /// The directory containing the plugin source and plugin.yaml
        dir: String,
        /// The output .vpa file path
        #[arg(short, long)]
        output: Option<String>,
        /// Optional path to an ED25519 private key to sign the plugin (creates signature.sig)
        #[arg(long)]
        sign: Option<String>,
    },
    /// Initialize a new plugin directory with boilerplate code
    Init {
        /// The name of the plugin
        name: String,
        /// The programming language to use (e.g. python, go)
        #[arg(long, default_value = "python")]
        lang: String,
        /// The runtime to use (grpc or wasm)
        #[arg(long, default_value = "grpc")]
        runtime: String,
    },
    /// Generate a new ED25519 keypair for signing plugins
    GenerateKey {
        /// The output path prefix for the generated keys (e.g., 'plugin_key' generates 'plugin_key.pem' and 'plugin_key.pub')
        #[arg(short, long, default_value = "valayam_plugin_key")]
        output: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_target() {
        let args = Args::parse_from(&["valayam"]);
        assert_eq!(args.target, "https://httpbin.org");
        assert!(args.template.is_none());
        assert!(args.nuclei_template.is_none());
        assert!(args.output.is_none());
        assert_eq!(args.format, "json");
        assert_eq!(args.concurrency, 500);
        assert_eq!(args.log_level, "info");
        assert_eq!(args.crawl_depth, 3);
    }

    #[test]
    fn test_custom_target_and_template() {
        let args = Args::parse_from(&["valayam", "-u", "https://example.com", "-t", "./templates/"]);
        assert_eq!(args.target, "https://example.com");
        assert_eq!(args.template, Some("./templates/".into()));
        assert!(args.nuclei_template.is_none());
    }

    #[test]
    fn test_output_and_format() {
        let args = Args::parse_from(&[
            "valayam", "-u", "https://test.com",
            "-o", "results.jsonl", "--format", "sarif",
        ]);
        assert_eq!(args.output, Some("results.jsonl".into()));
        assert_eq!(args.format, "sarif");
    }

    #[test]
    fn test_rate_limit_and_concurrency() {
        let args = Args::parse_from(&["valayam", "-r", "100", "--concurrency", "10"]);
        assert_eq!(args.rate_limit, Some(100));
        assert_eq!(args.concurrency, 10);
    }

    #[test]
    fn test_nuclei_template() {
        let args = Args::parse_from(&[
            "valayam", "-u", "https://test.com", "-n", "./nuclei-templates/",
        ]);
        assert_eq!(args.nuclei_template, Some("./nuclei-templates/".into()));
        assert!(args.template.is_none());
    }

    #[test]
    fn test_plugin_subcommand_package() {
        let args = Args::parse_from(&["valayam", "plugin", "package", "./my-plugin", "-o", "out.vpa"]);
        match args.command {
            Some(Commands::Plugin { action }) => match action {
                PluginCommands::Package { dir, output, sign } => {
                    assert_eq!(dir, "./my-plugin");
                    assert_eq!(output, Some("out.vpa".into()));
                    assert!(sign.is_none());
                }
                _ => panic!("Expected Package command"),
            },
            None => panic!("Expected a subcommand"),
        }
    }

    #[test]
    fn test_plugin_subcommand_init() {
        let args = Args::parse_from(&["valayam", "plugin", "init", "my-plugin"]);
        match args.command {
            Some(Commands::Plugin { action }) => match action {
                PluginCommands::Init { name, lang, runtime } => {
                    assert_eq!(name, "my-plugin");
                    assert_eq!(lang, "python");
                    assert_eq!(runtime, "grpc");
                }
                _ => panic!("Expected Init command"),
            },
            None => panic!("Expected a subcommand"),
        }
    }

    #[test]
    fn test_plugin_subcommand_init_custom_lang() {
        let args = Args::parse_from(&[
            "valayam", "plugin", "init", "my-go-plugin",
            "--lang", "go",
        ]);
        match args.command {
            Some(Commands::Plugin { action }) => match action {
                PluginCommands::Init { name, lang, .. } => {
                    assert_eq!(name, "my-go-plugin");
                    assert_eq!(lang, "go");
                }
                _ => panic!("Expected Init command"),
            },
            None => panic!("Expected a subcommand"),
        }
    }

    #[test]
    fn test_plugin_subcommand_generate_key() {
        let args = Args::parse_from(&["valayam", "plugin", "generate-key", "-o", "custom_key"]);
        match args.command {
            Some(Commands::Plugin { action }) => match action {
                PluginCommands::GenerateKey { output } => {
                    assert_eq!(output, "custom_key");
                }
                _ => panic!("Expected GenerateKey command"),
            },
            None => panic!("Expected a subcommand"),
        }
    }
}
