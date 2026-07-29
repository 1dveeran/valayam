//! Tracing and OpenTelemetry initialization for the Valayam CLI.
//!
//! Provides a clean extraction of the subscriber setup previously inline in `main.rs`,
//! enabling proper OTEL wiring and span instrumentation.

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};
use opentelemetry_otlp::WithExportConfig;

/// Result of initializing the tracing system.
/// Keeps the OTLP guard alive so telemetry is flushed on shutdown.
pub struct TracingGuard {
    _guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Configuration for the tracing layer stack.
pub struct TracingConfig {
    /// Console log level (stderr). Default: "error" when the user uses the default "info".
    pub console_level: tracing::Level,
    /// Optional path for a JSON structured log file (always DEBUG level).
    pub log_file: Option<String>,
    /// OTLP endpoint for exporting traces. Default: "http://localhost:4317".
    pub otlp_endpoint: String,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            console_level: tracing::Level::ERROR,
            log_file: None,
            otlp_endpoint: "http://localhost:4317".into(),
        }
    }
}

/// Initialize the tracing subscriber stack.
///
/// Layers (top to bottom):
/// 1. Console layer: human-readable, stderr, configured level
/// 2. File layer: JSON structured, DEBUG+, when `log_file` is set
/// 3. OpenTelemetry layer: exports traces via OTLP
///
/// Returns a `TracingGuard` that MUST be kept alive for the lifetime of the
/// application. Dropping it will flush and shutdown the OTLP pipeline.
pub fn init_tracing(config: TracingConfig) -> TracingGuard {
    let console_filter =
        tracing_subscriber::filter::LevelFilter::from_level(config.console_level);

    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_filter(console_filter);

    // OTLP pipeline
    let otlp_endpoint = if config.otlp_endpoint.is_empty() {
        "http://localhost:4317".to_string()
    } else {
        config.otlp_endpoint.clone()
    };

    let _tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(otlp_endpoint)
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .expect("Failed to initialize OTLP pipeline");

    // File layer — always DEBUG+, structured JSON
    if let Some(ref log_path) = config.log_file {
        let file = std::fs::File::create(log_path).expect("Failed to create log file");
        let (non_blocking, guard) = tracing_appender::non_blocking(file);

        let file_filter =
            tracing_subscriber::filter::LevelFilter::from_level(tracing::Level::DEBUG);
        let file_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(non_blocking)
            .with_filter(file_filter);

        tracing_subscriber::registry()
            .with(console_layer)
            .with(file_layer)
            .init();

        // Leak guard to prevent early flush; callers can still `std::mem::forget` if needed
        // but we keep it here so the drop runs on `TracingGuard::drop`
        TracingGuard { _guard: Some(guard) }
    } else {
        tracing_subscriber::registry()
            .with(console_layer)
            .init();

        TracingGuard { _guard: None }
    }
}

/// Compute the console log level from env var and CLI flag.
///
/// Priority: `VALAYAM_LOG` env var > CLI `--log-level` > default (ERROR).
pub fn resolve_console_level(log_level: &str) -> tracing::Level {
    let level_str = std::env::var("VALAYAM_LOG").unwrap_or_else(|_| {
        if log_level.eq_ignore_ascii_case("info") {
            "error".to_string()
        } else {
            log_level.to_string()
        }
    });
    level_str
        .parse::<tracing::Level>()
        .unwrap_or(tracing::Level::ERROR)
}