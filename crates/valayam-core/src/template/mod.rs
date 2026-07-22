// TODO: Implement Template Orchestrator and Schema (Phase 1).
// - schema.rs: Define the top-level VulnerabilityTemplate YAML serde structures (requests, network, scripts, compliance).
// - loader.rs: Orchestrate the execution pipeline (HTTP -> Network -> Scripts) ensuring the shared variable context flows correctly.
pub use valayam_models::templates::schema;
pub mod loader;
