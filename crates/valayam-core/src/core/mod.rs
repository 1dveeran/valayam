//! Core domain types for scan results, errors, and plugins.
//!
//! Provides the foundational data structures that flow through the engine:
//! scan results, error types, plugin definitions, and reporter implementations.

pub mod error;
pub mod plugins;
pub mod result;
pub mod scan_result_bridge;

pub mod reporters;