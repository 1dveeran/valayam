# ADR-005: Refinement & Housekeeping

**Status:** Accepted (2026-07-29)  
**Deciders:** Valayam Engineering Team  
**Tags:** maintenance, WASM, CLI, ergonomics

## Context

After major architectural changes (proto, observability, CI, audit), the project needed cleanup: oversized main.rs, inconsistent WASM plugin structures, undocumented architectural decisions, and missing CLI help for new flags.

## Decision

1. **Main.rs extraction**: Moved telemetry init to `tracing_init.rs`, scan orchestration to `orchestrator.rs`, CLI setup to `setup.rs`, CLI argument parsing to `cli.rs`. Main.rs reduced from ~400→341 lines — a clean coordinator calling into modules.
2. **WASM plugin crate-layering**: All 20 plugins under `plugins-wasm/` have proper Cargo.toml + src/lib.rs structure. Each is a workspace member. Plugin SDK provides shared types via `valayam-plugin-sdk`.
3. **Architecture Decision Records**: These ADR documents (`docs/adr/001` through `005`) capture rationale for each phase's design choices.
4. **CLI help update**: All new flags (`--tls-cert`, `--tls-key`, `--require-signed-plugins`) have clap doc strings visible in `--help`.

## Consequences

**Positive:** Main.rs is readable. Plugin onboarding is straightforward (copy an existing plugin dir). Architectural decisions are recorded for new contributors. CLI is self-documenting.  
**Negative:** ADRs must be kept current — risk of drift from actual implementation. WASM plugins have no test directories yet.  
**Risks:** ADRs become stale if not reviewed during code changes. Mitigated by ADR review in PR template.