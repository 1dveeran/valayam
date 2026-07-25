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

pub mod plugin_rpc {
    tonic::include_proto!("valayam.plugin");
    tonic::include_proto!("valayam");
}
pub mod host_functions;
