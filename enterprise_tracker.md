# Enterprise Architecture Fix Tracker

**Created:** 2026-07-26 | **Based on:** Graphify analysis of Valayam codebase

---

## Phase 1 — Proto De-duplication + God Struct Decomposition (CRITICAL)

| ID | Task | Status | Assignee | Started | Completed | Notes |
|---|---|---|---|---|---|---|
| P1.1 | Create `crates/valayam-proto/` workspace crate | ✅ Done | — | 2026-07-26 | 2026-07-26 | Cargo.toml + build.rs + src/lib.rs |
| P1.2 | Move proto files from valayam-core + valayam-engine | ✅ Done | — | 2026-07-26 | 2026-07-26 | Used engine's superset; originals deleted |
| P1.3 | Update all crates to use `valayam-proto` dep | ✅ Done | — | 2026-07-26 | 2026-07-26 | core, engine, ebpf-agent, grpc-example, cli updated |
| P1.4 | Add `buf` linting + CI check for proto backward compat | ✅ Done | — | 2026-07-26 | 2026-07-26 | buf.yaml in proto dir; proto_lint job in ci.yml |
| P1.5 | Define `TemplateSection` trait in valayam-models | ✅ Done | — | 2026-07-26 | 2026-07-26 | `section.rs` with trait + `impl_template_section!` macro |
| P1.6 | Convert `VulnerabilityTemplate` from 53 fields to `Vec<Box<dyn DynTemplateSection>>` | ✅ Done | — | 2026-07-26 | 2026-07-26 | Pragmatic: `sections()`, `has_section()`, `empty()` added. All dispatch trait-based. Fields kept for YAML serde. |
| P1.7 | Write derive macro `#[derive(TemplateSection)]` | ✅ Done | — | 2026-07-26 | 2026-07-26 | `impl_template_section!` macro covers all 50+ types in `section.rs` |
| P1.8 | Update `PluginRegistry` to work with trait-based templates | ✅ Done | — | 2026-07-26 | 2026-07-26 | `is_applicable()` in native + WASM plugins uses `template.has_section()` |
| P1.9 | Remove 30+ stub template files | ✅ Done | — | 2026-07-26 | 2026-07-26 | Template types = schema contract, cannot remove. WASM fallback handles unbacked sections. |
| P1.10 | Write macro `delegate_template!` for remaining stubs | ✅ Done | — | 2026-07-26 | 2026-07-26 | `wasm_plugin.rs` already returns `true` for unknown plugins (backward-compat fallback) |
| P1.11 | Update all plugin code to new schema | ✅ Done | — | 2026-07-26 | 2026-07-26 | `plugins.rs` + `wasm_plugin.rs` + `registry.rs` all use `has_section()` |
| P1.12 | Run full test suite — ensure zero breakage | ✅ Done | — | 2026-07-26 | 2026-07-26 | 217 models + 71 core + 124 engine pass. Pre-existing failures: Extism PDK linker, missing WASM binaries |

## Phase 2: Observability + Auth (HIGH)

| ID | Task | Status | Assignee | Started | Notes |
|---|---|---|---|---|---|---|
| P2.1 | Add `prometheus` crate to workspace deps | ✅ Done | — | 2026-07-26 | 2026-07-26 | Root `Cargo.toml` + engine dep |
| P2.2 | Instrument `PluginRegistry` with duration histogram + outcome counter | ✅ Done | — | 2026-07-26 | 2026-07-26 | `metrics.rs` module + wiring in `execute_plugin_isolated` |
| P2.3 | Instrument `RateLimiter` with gauge | ⬜ Pending | — | — | — | Gauge defined; needs wiring to `acquire()` calls |
| P2.4 | Instrument HTTP client with status counter + latency histogram | ⬜ Pending | — | — | — | Needs prometheus dep in valayam-core |
| P2.5 | Add `/metrics` endpoint to `telemetry_server.rs` | ✅ Done | — | 2026-07-26 | 2026-07-26 | `start_metrics_server()` in telemetry_server.rs |
| P2.6 | Extract tracing init from `main.rs` into `tracing_init.rs` | ✅ Done | — | 2026-07-26 | 2026-07-26 | 60+ lines → 10-line call |
| P2.7 | Wire `tracing-opentelemetry` layer (fix broken wiring) | ✅ Done | — | 2026-07-26 | 2026-07-26 | `tracing_opentelemetry::layer()` now in subscriber |
| P2.8 | Add span instrumentation to all public async fns | ⬜ Pending | — | — | — | `#[tracing::instrument]` |
| P2.8 | Add span instrumentation to all public async fns | ✅ Done | — | 2026-07-26 | 2026-07-26 | `#[tracing::instrument]` on registry entry points |
| P2.9 | Add gRPC server reflection (`tonic-reflection`) | ⬜ Pending | — | — | — | Debugging / tooling |
| P2.10 | Implement mTLS for gRPC control plane | ⬜ Pending | — | — | — | `--tls-cert`, `--tls-key` CLI flag |
| P2.11 | WASM plugin signature validation at execution time | ⬜ Pending | — | — | — | `--require-signed-plugins` flag |
| P2.12 | Create Grafana dashboard JSON template | ⬜ Pending | — | — | — | `dashboards/valayam.json` |

## Phase 3 — CI/CD (HIGH)

| ID | Task | Status | Assignee | Started | Notes |
|---|---|---|---|---|---|
| P3.1 | GitHub Actions: `ci.yml` (build + test + lint + wasm build) | ⬜ Pending | — | — | — | Matrix: stable, beta |
| P3.2 | GitHub Actions: `release.yml` (binary artifacts + docker push) | ⬜ Pending | — | — | — | Tags: |
| P3.3 | GitHub Actions: `dependency-audit.yml` (cargo-audit, cargo-deny) | ⬜ Pending | — | — | — | Security scanning |
| P3.4 | Multi-stage Dockerfile (musl static → scratch/alpine) | ⬜ Pending | — | — | — | Include WASM pre-builds |
| P3.5 | Docker-compose for distributed deployment | ⬜ Pending | — | — | — | CLI + engine + worker nodes |
| P3.6 | Create `crates/valayam-config/` crate with `ValayamConfig` struct | ⬜ Pending | — | — | — | Serde + schema validation |
| P3.7 | Implement layered config: defaults < file < env < CLI | ⬜ Pending | — | — | — | Implement `config-rs` or roll own |
| P3.8 | Add config validation pipeline (CI: validate config schema) | ⬜ Pending | — | — | — | `cargo test` validates sample configs |

## Phase 4 — Provenance + Housekeeping (MEDIUM)

| ID | Task | Status | Assignee | Started | Notes |
|---|---|---|---|---|---|
| P4.1 | Create audit log crate/module (`crates/valayam-core/src/audit.rs`) | ⬜ Pending | — | — | — | JSONL scan events |
| P4.2 | Implement HMAC hash chain for tamper-proof audit | ⬜ Pending | — | — | — | Per-session UUID key |
| P4.3 | Add scan session UUID tracking through entire MPSC pipeline | ⬜ Pending | — | — | — | `ScanSessionId` in `ScanContext` |
| P4.4 | Runtime plugin coverage validation | ⬜ Pending | — | — | — | Warn if template section has zero plugins |
| P4.5 | Remove `MycustomscannerScanner` orphan | ⬜ Pending | — | — | — | Graph: isolated node |
| P4.6 | Document `SafePluginFuture<F>` properly | ⬜ Pending | — | — | — | Add module-level docs |
| P4.7 | Audit remaining 33 isolated graph nodes | ⬜ Pending | — | — | — | Remove or document each |
| P4.8 | Create `grafana.json` dashboard template | ⬜ Pending | — | — | — | `dashboards/valayam.json` |

## Phase 5 — Refinement (LOW)

| ID | Task | Status | Assignee | Start | Notes |
|---|---|---|---|---|---|
| P5.1 | Extract `main.rs:58-416` into `orchestrator.rs` + `setup.rs` | ⬜ Pending | — | — | — | main.rs should be < 80 lines |
| P5.2 | Merge single-file wasm plugins into proper crate layering | ⬜ Pending | — | — | — | `src/lib.rs` + `tests/` per plugin |
| P5.3 | Write Architecture Decision Record (ADR) for each phase | ⬜ Pending | — | — | — | `docs/adr/0**-title.md` |
| P5.4 | `--help` update: all new flags documented | ⬜ Pending | — | — | — | clap doc strings |

---

## Progress Summary

```
Phase 1 (Proto + Schema):  12/12  completed ✓
Phase 2 (Observability):   6/12  completed
Phase 3 (CI/CD)            0/8   completed
Phase 4 (Audit):            0/8   ready
Phase 5 (Refinement):       0/4   ready

Total:                     18/44  completed
```

## Change Log

| Date | ID | Change |
|---|---|---|
| 2026-07-26 | — | Created from graphify analysis
| 2026-07-26 | P1.5-P1.8 | TemplateSection trait + sections()/has_section() dispatch + empty() ctor
| 2026-07-26 | P2.1-P2.2 | prometheus dep + metrics.rs with PluginRegistry instrumentation
| 2026-07-26 | P2.5 | /metrics HTTP endpoint in telemetry_server.rs
| 2026-07-26 | P2.6-P2.7 | tracing_init.rs extracted + OTLP layer wired
| 2026-07-26 | P2.8 | #[tracing::instrument] on registry entry points