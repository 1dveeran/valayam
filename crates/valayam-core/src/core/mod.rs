// TODO: Implement advanced Core Foundation components for Phase 1 & 4.
// - error.rs: Build a unified error enum mapping for all vertical slices to serialize into ScanResult.
// - variables.rs: Finalize the shared context hashmap for {{variable}} substitution across templates.
// - rate_limiter.rs: Harden the global token-bucket RPS governor (governor crate) for thread-safe async batch processing.
// - result.rs: Ensure ScanResult structs cleanly serialize to JSON for CLI output and SIEM integration.
pub mod error;
pub mod executor;
pub mod matcher;
pub mod matchers;
pub mod plugin_macro;
pub mod plugins;
pub mod rate_limiter;
pub mod registry;
pub mod reporters;
pub mod result;
pub mod scan_result_bridge;
pub mod traits;
pub mod variables;
