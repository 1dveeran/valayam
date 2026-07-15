// TODO: Implement Hardcoded Secrets Discovery (Phase 27).
// - High-entropy regex scanning across entire repositories for API keys.
// - Filter out common test data and mock secrets to reduce noise.
// - Integrate with Git history parsing to find deleted secrets.
pub mod parser;
pub mod executor;
