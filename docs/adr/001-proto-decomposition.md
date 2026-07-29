# ADR-001: Proto De-duplication & God Struct Decomposition

**Status:** Accepted (2026-07-26)  
**Deciders:** Valayam Engineering Team  
**Tags:** proto, protobuf, schema, macros

## Context

The codebase had duplicated protobuf definitions across `valayam-core` and `valayam-engine`, causing schema drift and compilation issues during gRPC changes. 53-field `VulnerabilityTemplate` god struct was a monolithic barrier to plugin extensibility — adding a new template section required modifying the struct itself.

## Decision

1. **Centralized proto crate**: Create `crates/valayam-proto/` as the sole proto definition source. All crates depend on it. Single `build.rs` with `tonic-build`.
2. **Buf linting**: Add `buf` CI job for backward compatibility checking.
3. **TemplateSection trait**: Decompose `VulnerabilityTemplate` into `DynTemplateSection` trait + `Vec<Box<dyn DynTemplateSection>>`. Each section type implements the trait via `impl_template_section!` macro.
4. **Pragmatic fields**: Keep raw fields on `VulnerabilityTemplate` for YAML serde; trait dispatch sits on top via `sections()`/`has_section()`.
5. **WASM fallback**: Unknown template sections default to `true` in `is_applicable()` (backward-compatible).

## Consequences

**Positive:** Zero duplicated proto definitions. Adding a new section is a single-file change — implement the trait, register in the section list. gRPC service discovery works from any crate.  
**Negative:** Slight memory overhead from `Vec<Box<dyn ...>>` indirection. Build time increased by proto compilation. Some test fixtures needed schema updates.  
**Risks:** WASM fallback may hide misconfigurations — a plugin returning `true` for everything is indistinguishable from "no applicable plugin found."