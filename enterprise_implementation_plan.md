# Valayam — Enterprise Implementation Plan

**Based on:** Graphify analysis (2960 nodes, 4192 edges, 750 communities) + full codebase audit
**Date:** 2026-07-26

---

## Gap → Fix Mapping

| # | Gap | Fix | Priority | Effort |
|---|---|---|---|---|
| G1 | God Struct `VulnerabilityTemplate` (53 fields, 584 thin communities) | Trait-based decomposition + builder pattern | CRITICAL | Large |
| G2 | 33 isolated nodes — orphan/dead code | Audit + remove or document all isolated symbols | CRITICAL | Small |
| G3 | 46 INFERRED edges for `run_plugin()`/`build_wasm()` — dynamic dispatch ambiguity | Compile-time plugin registry with exhaustive match | HIGH | Medium |
| G4 | No observability stack (Prometheus/OTEL metrics, dashboards) | Add metrics layer, Grafana dashboard template | HIGH | Medium |
| G5 | Duplicate `.proto` files in two crates | Single source of truth with shared proto crate | HIGH | Small |
| G6 | No CI/CD pipeline | GitHub Actions + Docker + release workflow | HIGH | Medium |
| G7 | No auth/authz on gRPC or WASM | mTLS for gRPC, signed WASM verification | HIGH | Medium |
| G8 | No centralized configuration | Structured config crate with schema validation | MEDIUM | Medium |
| G9 | No audit logging or scan provenance | Audit log crate + scan session tracking | MEDIUM | Small |
| G10 | Stub farm — 50+ template types with no executor logic | Auto-generate from macro or remove until implemented | MEDIUM | Small |
| G11 | main.rs monolithic (420 lines) | Extract to orchestration modules | MEDIUM | Small |
| G12 | 584 thin communities — low cohesion across the board | Reorganize WASM plugins into single workspace sub-crate per audit type | LOW | Large |

---

## Implementation Phases

### Phase 1 — Proto De-duplication + God Struct Decomposition (CRITICAL)

**Goal:** Eliminate proto drift, reduce `VulnerabilityTemplate` from 53 fields to composable traits.

**Tasks:**

1. **Create `proto/` workspace crate** — single source for `.proto` files
   - Move proto from both `valayam-core` and `valayam-engine` into `crates/valayam-proto/`
   - Both crates depend on `valayam-proto` instead of own `include_proto!`
   - Add proto linting via `buf` in CI
   - Files: `crates/valayam-proto/Cargo.toml`, `crates/valayam-proto/src/lib.rs`

2. **Decompose `VulnerabilityTemplate`** via traits
   - Define `trait TemplateSection { fn validate(&self) -> Result<(), ScannerError>; }`
   - Each template type implements `TemplateSection` + `DynTemplateSection`
   - `VulnerabilityTemplate` holds `Vec<Box<dyn DynTemplateSection>>` instead of 53 named fields
   - Macro `#[derive(TemplateSection)]` to auto-implement for consistent types
   - Files: `crates/valayam-models/src/traits.rs`, `crates/valayam-models/src/templates/schema.rs`

3. **Remove stub-farm** — 50+ empty template types
   - Keep only template types with actual executor logic (http_scan, dns_audit, tls_audit, port_scan, network_scan, fuzzer, scripting, crawler, oob, threat_intel, schema_drift)
   - All others: macro `delegate_template! { scada_audit => GenericScanner }` — one-line declarations
   - Files: `crates/valayam-models/src/templates/*.rs`

### Phase 2 — Observability + Auth (HIGH)

**Goal:** Production-ready observability and secure gRPC.

**Tasks:**

4. **Metrics layer**
   - Add `prometheus` crate to workspace deps
   - Instrument `PluginRegistry`: histogram for execution duration, counter for outcomes
   - Instrument `RateLimiter`: gauge for current permit count
   - Instrument HTTP client: counter for status codes, histogram for latencies
   - Expose `/metrics` endpoint in `telemetry_server.rs`
   - Files: `crates/valayam-engine/src/metrics.rs`, `crates/valayam-engine/src/telemetry_server.rs`

5. **Structured tracing wiring**
   - Move tracing/OTEL init from `main.rs:67-114` into a dedicated `tracing_init.rs`
   - Wire `tracing-opentelemetry` layer properly (currently commented out at main.rs:90-92)
   - Add span instrumentation to all public async fns
   - Files: `crates/valayam-cli/src/tracing_init.rs`

6. **gRPC mTLS + reflection**
   - Add `tonic-reflection` for server reflection
   - Add rustls build with client certs for mTLS
   - Add `--tls-cert` and `--tls-key` CLI flags
   - Validate peer certs on connect
   - Files: `crates/valayam-engine/src/telemetry_server.rs`

7. **WASM plugin signature enforcement**
   - Validate `PluginCrypto` signature check at *execution* time, not just install time
   - Add runtime flag `--require-signed-plugins`
   - Files: `crates/valayam-engine/src/registry.rs`, `crates/valayam-engine/src/crypto.rs`

### Phase 3 — CI/CD + Configuration (HIGH)

**Goal:** Automated build/release pipeline + structured config.

**Tasks:**

8. **GitHub Actions CI**
   ```
   .github/workflows/ci.yml — build, test, lint, WASM build
   .github/workflows/release.yml — binary artifact + docker push
   .github/workflows/dependency-review.yml — cargo-audit, dependency review
   ```

9. **Docker build**
   - Multi-stage Dockerfile: musl static build → scratch/alpine
   - Include WASM plugin pre-builds in image
   - Docker-compose for distributed: CLI → engine → worker nodes
   - Files: `Dockerfile`, `tests/e2e/docker-compose.yml`

10. **Configuration crate**
    - `crates/valayam-config/` with `ValayamConfig` struct
    - Serde with schema validation (broken path catches, required fields)
    - CLI arguments → Config override (layered config: defaults < file < env < CLI)
    - Files: `crates/valayam-config/Cargo.toml`, `crates/valayam-config/src/lib.rs`

### Phase 4 — Audit + Provenance + Runtime Validation (MEDIUM)

**Goal:** Enterprise audit compliance.

**Tasks:**

11. **Audit logging**
    - Structured audit events (scan started, plugin executed, finding emitted, scan completed)
    - Stored as JSONL with UUIDs for each scan session
    - Tamper-proof via HMAC hash chain
    - Files: `crates/valayam-core/src/audit.rs`

12. **Runtime plugin validation**
    - Compile-time registration: `PluginRegistry::with_registration` macro asserts all plugins are covered
    - At startup: validate all declared template sections have at least 1 plugin registered
    - Emit warning for any template type with zero executor coverage
    - Files: `crates/valayam-engine/src/registry.rs`

13. **Cleanup isolated nodes**
    - Remove `MycustomscannerScanner` (example code)
    - Move `SafePluginFuture<F>` into proper module docs
    - Audit and implement or remove all 33 isolated graph nodes
    - Files: various

### Phase 4 — Refinement (LOW)

**Tasks:**

14. **CLI refactor** — Extract `main.rs:58-56` into orchestration modules
15. **Compress WASM plugins** — Merge single-file wasm plugins into crates with proper lib + test layering
16. **Documentation** — Architecture Decision Record for each phase

---

## Dependency Order

```
Phase 1 (Critical)  →  Must complete first
Phase 2 (Observability) →  Independent (can run parallel with Phase 1)
Phase 3 (CI/CD)      →  Independent (can run parallel with Phase 1 + 2)
Phase 4 (Audit)      →  Depends on Phase 2 (observability setup)
Phase 5 (Refinement) →  No dependencies
```

---

## Success Criteria

| Metric | Current | Target |
|---|---|---|
| Thin communities (< 3 nodes) | 584 (78%) | < 50 |
| God node edges (`VulnerabilityTemplate`) | 78 | < 20 |
| Inferred edges (runtime ambiguity) | 103 | < 10 |
| Isolated nodes | 33 | 0 |
| Prometheus metrics exported | 0 | 10+ (duration, count, gauge for each subsystem) |
| CI builds passing | None | 3 workflows green |
| Configurable auth | None | mTLS + optional plugin signing |
| VPA type compile-time coverage | Dynamic dispatch | Exhaustive registration validation |

---

## File Inventory Affected

### Phase 1
```
crates/valayam-proto/Cargo.toml              (NEW)
crates/valayam-proto/src/lib.rs              (NEW)
crates/val /valayam-core/proto/*.proto       (MOVE → valayam-proto)
crates/valayam-engine/proto/*.proto          (MOVE → valayam-proto)
crates/valayam-core/src/lib.rs               (EDIT: use valayam-proto)
crates/valayam-engine/src/lib.rs             (EDIT: use valayam-proto)
crates/valayam-models/src/template.rs         (NEW: Trait definition)
crates/valayam-models/src/templates/schema.rs (MAJOR EDIT: trait decomposition)
crates/valayam-models/src/templates/*.rs     (DELETE: 30+ stub files)
crates/valayam-core/src/core/plugins.rs      (EDIT: adapt to new schema)
crates/valayam-engine/src/registry.rs         (EDIT: adapt to new schema)
```

### Phase 2
```
crates/valayam-engine/src/metrics.rs          (NEW)
crates/valayam-engine/src/telemetry_server.rs (EDIT: add /metrics, mTLS)
crates/valayam-cli/src/tracing_init.rs         (NEW: extract from main.rs)
crates/valayam-cli/src/main.rs                (EDIT: use tracing_init)
crates/valayam-engine/Cargo.toml              (ADD: prometheus, tonic-reflection)
```

### Phase 3
```
.github/workflows/ci.yml                     (NEW)
.github/workflows/release.yml                (NEW)
Dockerfile                                    (NEW)
tests/e2e/docker-compose.yml                 (EDIT: extend)
crates/valayam-config/Cargo.toml             (NEW)
crates/valayam-config/src/lib.rs             (NEW)
```

### Phase 4
```
crates/valayam-core/src/audit.rs              (NEW)
crates/valayam-engine/src/registry.rs         (EDIT: runtime coverage check)
```

---

## Estimated Timeline

| Phase | Duration | Effort |
|---|---|---|
| Phase 1 — Proto + God Struct | 2-3 weeks | Heavy refactor, touch ~30 files |
| Phase 2 — Observability + Auth | 1-2 weeks | Add new code, limited refactor |
| Phase 3 — CI/CD + Config | 1 week | New files only, no refactor |
| Phase 4 — Audit + Cleanup | 1 week | Small scope, targeted |
| Phase 5 — Refinement | 1 week | Polishing |

Total: ~6-8 weeks to enterprise-grade readiness.