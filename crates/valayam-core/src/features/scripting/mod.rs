// TODO: Implement Embedded Rhai Scripting Engine (Phase 3).
// - engine.rs: Configure strict sandboxing (max_operations, call stack limits).
// - executor.rs: Inject HTTP, Regex, TCP, Crypto, and WebSocket built-ins.
// - Implement secure variable bridge (`get_variable`, `set_variable`) for workflow state.
pub mod parser;
pub mod engine;
pub mod executor;
