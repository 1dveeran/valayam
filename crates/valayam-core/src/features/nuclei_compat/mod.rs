// TODO: Implement Nuclei Template Compatibility (Phase 3).
// - Isolated execution engine for parsing standard HTTP Nuclei templates.
// - Support `matchers-condition: and|or` for flexible logic.
// - Prevent architectural pollution by strictly sandboxing the engine.

pub mod executor;
pub mod matchers;
