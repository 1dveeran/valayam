# ADR-003: CI/CD Pipeline & Configuration

**Status:** Accepted (2026-07-26)  
**Deciders:** Valayam Engineering Team  
**Tags:** CI, CD, docker, config

## Context

The project had no automated CI, making it impossible to verify builds across platforms or catch regressions. No release artifacts or container images were published. Configuration was scattered across CLI flags and magic constants in source files.

## Decision

1. **GitHub Actions CI** (`ci.yml`): Build + test + lint (clippy, rustfmt) on stable and beta. WASM plugin pre-build step ensures plugin compatibility.
2. **Release pipeline** (`release.yml`): Multi-arch binary artifacts (x86_64, aarch64). Docker image build and push to GHCR.
3. **Dependency audit** (`dependency-audit.yml`): Weekly `cargo-audit` for CVEs, `cargo-deny` for license compliance. Triggers on `Cargo.toml` changes.
4. **Multi-stage Dockerfile**: MUSL statically-linked binary → distroless scratch image (~15MB). WASM binaries baked in.
5. **Docker Compose**: Prometheus + Grafana + OTEL collector + worker node for distributed deployment.
6. **Centralized config crate** (`valayam-config`): Single `ValayamConfig` struct with serde YAML deserialization. Layered priority: built-in defaults → config file → `VALAYAM_*` env vars → CLI flags. Validation pipeline returns typed `ConfigError` for broken paths, invalid URLs, conflicting flags.

## Consequences

**Positive:** Every PR is automatically built and linted. Dependency vulnerabilities caught weekly. Single command to deploy full observability stack. Config validation catches misconfiguration at startup.  
**Negative:** WASM pre-build step adds ~3 min to CI. Multi-arch Docker builds require QEMU emulation (slow on x86 runners). Weekly audit runs may pile up if left untriaged.  
**Risks:** Config file's `deny_unknown_fields` will reject configs from older versions if new fields are added — requires migration path.