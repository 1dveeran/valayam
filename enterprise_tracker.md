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
| P1.5 | Define `TemplateSection` trait in valayam-models | ⬜ Pending | — | — | — | `trait TemplateSection { fn validate(); }` |
| P1.6 | Convert `VulnerabilityTemplate` from 53 fields to `Vec<Box<dyn DynTemplateSection>>` | ⬜ Pending | — | — | — | Major refactor |
| P1.7 | Write derive macro `#[derive(TemplateSection)]` | ⬜ Pending | — | — | — | Procedural macro or `macro_rules!` |
| P1.8 | Update `PluginRegistry` to work with trait-based templates | ⬜ Pending | — | — | — | `is_applicable()` now works on sections |
| P1.9 | Remove 30+ stub template files | ⬜ Pending | — | — | — | Keep only types with executor logic |
| P1.10 | Write macro `delegate_template!` for remaining stubs | ⬜ Pending | — | — | — | One-liner: `delegate_template! { scada => Generic }` |
| P1.11 | Update all plugin code to new schema | ⬜ Pending | — | — | — | 12+ PLUGIN files |
| P1.12 | Run full test suite — ensure zero breakage | ⬜ Pending | — | — | — | `cargo test --workspace` |

## Phase 2: Observability + Auth (HIGH)

| ID | Task | Status | Assignee | Started | Notes |
|---|---|---|---|---|---|
| P2.1 | Add `prometheus` crate to workspace deps | ⬜ Pending | — | — | — | Root `Cargo.toml` |
| P2.2 | Instrument `PluginRegistry` with duration histogram + outcome counter | ⬜ Pending | — | — | — | `plugin_execution_duration_seconds`, `plugin_outcome_total` |
| P2.3 | Instrument `RateLimiter` with gauge | ⬜ Pending | — | — | — | `rate_limiter_permits_available` |
| P2.4 | Instrument HTTP client with status counter + latency histogram | ⬜ Pending | — | — | — | `http_request_total`, `http_request_duration_seconds` |
| P2.5 | Add `/metrics` endpoint to `telemetry_server.rs` | ✅ Done | — | 2026-07-26 | — | Telemetry server with TLS + metrics endpoint |
| P2.6 | Extract tracing init from `main.rs` into `tracing_init.rs` | ⬜ Pending | — | — | — | Clean up years 60-114 of `main.rs` |
| P2.7 | Wire `tracing-opentelemetry` layer (fix broken wiring) | ⬜ Pending | — | — | — | Fix comment at main.rs:90-92 |
| P2.8 | Add span instrumentation to all public async fns | ⬜ Pending | — | — | — | `#[tracing::instrument]` |
| P2.9 | Add gRPC server reflection (`tonic-reflection`) | ⬜ Pending | — | — | — | Debugging / tooling |
| P2.10 | Implement mTLS for gRPC control plane | ✅ Done | — | 2026-07-26 | — | `--tls-cert`, `--tls-key` CLI flags |
| P2.11 | WASM plugin signature validation at execution time | ✅ Done | — | 2026-07-26 | — | `--require-signed-plugins` flag |
| P2.12 | Create Grafana dashboard JSON template | ✅ Done | — | 2026-07-26 | — | `dashboards/valayam.json` |

## Phase 3 — CI/CD (HIGH)

| ID | Task | Status | Assignee | Started | Notes |
|---|---|---|---|---|---|
| P3.1 | GitHub Actions: `ci.yml` (build + test + lint + wasm build) | ✅ Done | — | 2026-07-26 | — | Matrix: stable, beta |
| P3.2 | GitHub Actions: `release.yml` (binary artifacts + docker push) | ✅ Done | — | 2026-07-26 | — | Multi-arch + docker push |
| P3.3 | GitHub Actions: `dependency-audit.yml` (cargo-audit, cargo-deny) | ✅ Done | — | 2026-07-26 | — | Weekly + on Cargo.toml changes |
| P3.4 | Multi-stage Dockerfile (musl static → scratch/alpine) | ✅ Done | — | 2026-07-26 | — | Including WASM pre-builds |
| P3.5 | Docker-compose for distributed deployment | ✅ Done | — | 2026-07-26 | — | Prometheus + Grafana + OTEL + worker |
| P3.6 | Create `crates/valayam-config/` crate with `ValayamConfig` struct | ⬜ Pending | — | — | — | Serde + schema validation |
| P3.7 | Implement layered config: defaults < file < env < CLI | ⬜ Pending | — | — | — | Implement `config-rs` or roll own |
| P3.8 | Add config validation pipeline (CI: validate config schema) | ⬜ Pending | — | — | — | `cargo test` validates sample configs |

## Phase 4 — Provenance + Housekeeping (MEDIUM)

| ID | Task | Status | Assignee | Started | Notes |
|---|---|---|---|---|---|
| P4.1 | Create audit log crate/module (`crates/valayam-core/src/audit.rs`) | ✅ Done | — | 2026-07-26 | — | JSONL scan events |
| P4.2 | Implement HMAC hash chain for tamper-proof audit | ✅ Done | — | 2026-07-26 | — | Per-session UUID key |
| P4.3 | Add scan session UUID tracking through entire MPSC pipeline | ✅ Done | — | 2026-07-26 | — | `scan_id: Uuid` in `ScanContext` + `FindingOwned` |
| P4.4 | Runtime plugin coverage validation | ✅ Done | — | 2026-07-26 | — | Warns if template sections have zero applicable plugins |
| P4.5 | Remove `MycustomscannerScanner` orphan | ✅ Done | — | 2026-07-26 | — | `my-custom-scanner/` directory deleted |
| P4.6 | Document `SafePluginFuture<F>` properly | ✅ Done | — | 2026-07-26 | — | Module-level docs in `unwind_safe.rs` |
| P4.7 | Audit remaining 33 isolated graph nodes | ⬜ Pending | — | — | — | Needs graphify analysis |
| P4.8 | Create `grafana.json` dashboard template | ✅ Done | — | 2026-07-26 | — | `dashboards/valayam.json` |

## Phase 5 — Refinement (LOW)

| ID | Task | Status | Assignee | Start | Notes |
|---|---|---|---|---|---|
| P5.1 | Extract `main.rs:58-416` into `orchestrator.rs` + `setup.rs` | ⬜ Pending | — | — | — | main.rs still ~400 lines; orchestrator exists but setup code remains in main |
| P5.2 | Merge single-file wasm plugins into proper crate layering | ⬜ Pending | — | — | — | `src/lib.rs` + `tests/` per plugin |
| P5.3 | Write Architecture Decision Record (ADR) for each phase | ⬜ Pending | — | — | — | `docs/adr/0**-title.md` |
| P5.4 | `--help` update: all new flags documented | ✅ Done | — | 2026-07-26 | — | clap doc strings on `--tls-cert`, `--tls-key`, `--require-signed-plugins` |

---

## Progress Summary

```
Phase 1 (Proto + Schema):  4/12  completed
Phase 2 (Observability):   4/12  completed
Phase 3 (CI/CD)            5/8   completed
Phase 4 (Audit):            7/8   ready
Phase 5 (Refinement):       1/4   ready

Total:                     21/44 completed
```

## Change Log

| Date | ID | Change |
|---|---|---|
| 2026-07-26 | — | Created from graphify analysis |
| 2026-07-28 | P2.5,P2.10-P2.12 | Telemetry TLS, mTLS flags, plugin sig validation, Grafana dashboard |
| 2026-07-28 | P3.1-P3.5 | CI/CD pipeline: ci.yml + release.yml + dependency-audit + Docker + compose |
| 2026-07-28 | P4.1-P4.6,P4.8 | Audit module, HMAC chain, scan_id, coverage validation, cleanup |
| 2026-07-28 | P5.4 | CLI --help for all new flags |