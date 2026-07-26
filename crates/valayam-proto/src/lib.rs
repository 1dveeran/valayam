//! Shared proto definitions for the Valayam workspace.
//!
//! This crate is the single source of truth for all gRPC protobuf definitions.
//! All other crates depend on this one instead of compiling their own protos.

/// Core Valayam scanner RPCs — scan, telemetry, and control plane.
pub mod valayam {
    tonic::include_proto!("valayam");
}

/// Plugin service RPCs — external plugin lifecycle (init, execute, shutdown).
pub mod plugin {
    tonic::include_proto!("valayam.plugin");
}