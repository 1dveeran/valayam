# ADR-002: Observability & Auth Infrastructure

**Status:** Accepted (2026-07-26)  
**Deciders:** Valayam Engineering Team  
**Tags:** metrics, tracing, telemetry, mTLS, WASM signing

## Context

The platform lacked visibility into plugin execution, HTTP request outcomes, and rate-limiter pressure. Debugging issues involved adding ad-hoc `println!` statements. The gRPC control plane had no transport security. WASM plugins could be loaded without integrity verification.

## Decision

1. **Prometheus metrics**: Use `prometheus` crate with global `lazy_static` metric registration. Three metric domains:
   - Plugin execution: `valayam_plugin_duration_seconds`, `valayam_plugin_outcome_total`, `valayam_plugin_finding_total`
   - HTTP requests: `valayam_http_requests_total`, `valayam_http_request_duration_seconds`
   - Rate limiter: `valayam_rate_limiter_permits_available`
2. **OpenTelemetry tracing**: `tracing_init.rs` extracted from `main.rs`. Wired `tracing-opentelemetry` layer for OTLP export. `#[tracing::instrument]` on registry entry points.
3. **`/metrics` HTTP endpoint**: Dedicated `telemetry_server.rs` with `start_metrics_server()` for Prometheus scrape.
4. **mTLS for gRPC**: `--tls-cert` and `--tls-key` CLI flags. `TlsConfig` struct passed to the gRPC server builder.
5. **WASM plugin signing**: Ed25519 signature validation via `--require-signed-plugins` flag. Verifies plugin manifest signatures at load time.
6. **Grafana dashboard**: `dashboards/valayam.json` with plugin latency/throughput, HTTP error rates, rate-limiter saturation panels.

## Consequences

**Positive:** Every plugin execution is measured. HTTP latency surfaced. gRPC control plane can be secured in production. WASM supply-chain attacks mitigated.  
**Negative:** Prometheus global registry creates implicit coupling — any crate importing metrics registers globally. OTLP exporter adds startup latency. Signed plugins increase CI complexity.  
**Risks:** Global metric registration can panic on name collision if two crates define the same metric name. Mitigated by `valayam_` prefix convention.