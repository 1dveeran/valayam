//! Prometheus metrics instrumentation for the Valayam engine.
//!
//! Exposes counters, histograms, and gauges for:
//! - Plugin execution duration + outcome
//! - Rate limiter state
//! - HTTP client status codes + latency
//! - Scan-level progress
//!
//! All metrics use the default `prometheus` registry and are
//! exported via the `/metrics` HTTP endpoint in `telemetry_server.rs`.

use once_cell::sync::Lazy;
use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec, CounterVec, Gauge, HistogramVec,
};

// ── Plugin metrics ───────────────────────────────────────────────────────

/// Histogram of plugin execution duration in seconds.
/// Labels: plugin_name, outcome (matched|no_match|skipped|failed)
pub static PLUGIN_EXECUTION_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "valayam_plugin_execution_duration_seconds",
        "Plugin execution duration in seconds",
        &["plugin_name", "outcome"],
        vec![0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]
    )
    .expect("PLUGIN_EXECUTION_DURATION metric registration failed")
});

/// Counter of plugin executions by outcome.
/// Labels: plugin_name, outcome
pub static PLUGIN_OUTCOME_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "valayam_plugin_outcome_total",
        "Total number of plugin executions by outcome",
        &["plugin_name", "outcome"]
    )
    .expect("PLUGIN_OUTCOME_TOTAL metric registration failed")
});

/// Counter of findings emitted by each plugin.
/// Labels: plugin_name, severity
pub static PLUGIN_FINDINGS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "valayam_plugin_findings_total",
        "Total number of findings emitted by plugin and severity",
        &["plugin_name", "severity"]
    )
    .expect("PLUGIN_FINDINGS_TOTAL metric registration failed")
});

// ── Rate limiter metrics ─────────────────────────────────────────────────

/// Gauge of currently available rate limiter permits (approximate).
pub static RATE_LIMITER_PERMITS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "valayam_rate_limiter_permits_available",
        "Approximate number of available rate limiter permits"
    )
    .expect("RATE_LIMITER_PERMITS metric registration failed")
});

/// Gauge of the current backoff multiplier (1 = no backoff).
pub static RATE_LIMITER_BACKOFF_MULTIPLIER: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "valayam_rate_limiter_backoff_multiplier",
        "Current backoff multiplier applied to rate limiting"
    )
    .expect("RATE_LIMITER_BACKOFF_MULTIPLIER metric registration failed")
});

/// Counter of 429 rate-limit responses received across all HTTP clients.
pub static HTTP_429_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "valayam_http_429_total",
        "Total number of HTTP 429 responses received",
        &["host"]
    )
    .expect("HTTP_429_TOTAL metric registration failed")
});

// ── HTTP client metrics ──────────────────────────────────────────────────

/// Counter of HTTP requests by status code class.
/// Labels: status_class (2xx, 3xx, 4xx, 5xx)
pub static HTTP_REQUEST_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "valayam_http_request_total",
        "Total number of HTTP requests by status code class",
        &["status_class", "host"]
    )
    .expect("HTTP_REQUEST_TOTAL metric registration failed")
});

/// Histogram of HTTP request duration in seconds.
/// Labels: host
pub static HTTP_REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "valayam_http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["host"],
        vec![0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0]
    )
    .expect("HTTP_REQUEST_DURATION metric registration failed")
});

// ── Scan-level metrics ───────────────────────────────────────────────────

/// Gauge of the number of templates loaded for the current scan.
pub static SCAN_TEMPLATES_LOADED: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "valayam_scan_templates_loaded",
        "Number of templates loaded for the current scan"
    )
    .expect("SCAN_TEMPLATES_LOADED metric registration failed")
});

/// Gauge of the number of targets being scanned.
pub static SCAN_TARGETS_TOTAL: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "valayam_scan_targets_total",
        "Number of targets in the current scan"
    )
    .expect("SCAN_TARGETS_TOTAL metric registration failed")
});

/// Gauge of the current scan state (0=running, 1=paused, 2=cancelled, 3=completed).
pub static SCAN_STATE: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "valayam_scan_state",
        "Current scan state: 0=running, 1=paused, 2=cancelled, 3=completed"
    )
    .expect("SCAN_STATE metric registration failed")
});

/// Counter of findings emitted by severity.
/// Labels: severity
pub static FINDINGS_BY_SEVERITY: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "valayam_findings_by_severity_total",
        "Total findings by severity level",
        &["severity"]
    )
    .expect("FINDINGS_BY_SEVERITY metric registration failed")
});

/// Helper: record plugin metrics from tracing info.
pub fn record_plugin_outcome(plugin_name: &str, outcome: &str, duration_secs: f64, finding_count: usize) {
    PLUGIN_EXECUTION_DURATION
        .with_label_values(&[plugin_name, outcome])
        .observe(duration_secs);
    PLUGIN_OUTCOME_TOTAL
        .with_label_values(&[plugin_name, outcome])
        .inc();
    if finding_count > 0 {
        PLUGIN_FINDINGS_TOTAL
            .with_label_values(&[plugin_name, "unknown"])
            .inc_by(finding_count as f64);
    }
}

/// Helper: record HTTP request metrics.
pub fn record_http_request(host: &str, status_code: u16, duration_secs: f64) {
    let class = match status_code {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "unknown",
    };
    HTTP_REQUEST_TOTAL
        .with_label_values(&[class, host])
        .inc();
    HTTP_REQUEST_DURATION
        .with_label_values(&[host])
        .observe(duration_secs);
    if status_code == 429 {
        HTTP_429_TOTAL.with_label_values(&[host]).inc();
    }
}

/// Helper: record a finding by severity.
pub fn record_finding(severity: &str) {
    FINDINGS_BY_SEVERITY
        .with_label_values(&[severity])
        .inc();
}

/// Helper: update rate limiter metrics from stats.
pub fn update_rate_limiter_metrics(permits_available: f64, backoff_multiplier: f64) {
    RATE_LIMITER_PERMITS.set(permits_available);
    RATE_LIMITER_BACKOFF_MULTIPLIER.set(backoff_multiplier);
}

/// Gather all prometheus metrics as text for the /metrics endpoint.
pub fn gather_metrics() -> String {
    use prometheus::TextEncoder;
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    encoder.encode_to_string(&metric_families).unwrap_or_else(|e| {
        format!("# Error encoding metrics: {}\n", e)
    })
}