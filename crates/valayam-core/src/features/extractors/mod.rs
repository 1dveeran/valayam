//! Dynamic value extraction from HTTP responses.
//!
//! Supports Regex, JSON Pointer, and CSS Selector extraction types.
//! Extracted values populate the shared variables map for downstream use.

pub mod engine;