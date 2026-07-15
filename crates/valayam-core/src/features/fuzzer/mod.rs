// TODO: Implement Active Parameter Fuzzing Engine (Phase 6).
// - executor.rs: Mutate URL query parameters safely without leaking across threads.
// - Evaluate mutated responses using generic anomaly detection matchers (e.g. 500 status).
// - Support isolated fuzzing targets (e.g. only designated keys).
pub mod parser;
pub mod executor;
