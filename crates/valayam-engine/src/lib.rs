pub mod executor;
pub mod matchers;
pub mod plugin_macro;
pub mod rate_limiter;
pub mod registry;
pub mod traits;
pub mod unwind_safe;
pub mod variables;
pub mod grpc_plugin;
pub mod wasm_plugin;
pub mod vpa;
pub mod crypto;
pub mod telemetry_server;

// Re-exported from valayam-proto (single source of truth)
pub use valayam_proto::plugin as plugin_rpc;
pub use valayam_proto::valayam as rpc;
pub mod host_functions;
