//! Schema drift detection — native OpenAPI document parsing and endpoint diffing.
//!
//! Parses OpenAPI specs, crawls target applications, and cross-references
//! active endpoints against the specification to flag undocumented shadow APIs
//! and abandoned zombie API routes. Generates diff reports for developer feedback.

pub mod executor;