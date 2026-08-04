//! Scan execution engine for Valayam.
//!
//! Central orchestrator: plugin registry with topological execution, WASM/gRPC
//! plugin bridges, rate limiting with adaptive backoff, variable resolution,
//! retry logic with exponential backoff, telemetry, and crypto verification.
//! All scan execution flows through this crate.
pub mod executor;
pub mod matchers;
pub mod metrics;
pub mod plugin_macro;
pub mod rate_limiter;
pub mod reflection;
pub mod registry;
pub mod scan_state;
pub mod traits;
pub mod unwind_safe;
pub mod variables;
pub mod grpc_plugin;
pub mod wasm_plugin;
pub mod vpa;


// Re-exported from valayam-proto (single source of truth)
pub use valayam_proto::plugin as plugin_rpc;
pub use valayam_proto::valayam as rpc;
pub mod host_functions;
