// TODO: Implement HTTP Request Scanning (Phase 1).
// - parser.rs: Define YAML structures for custom methods, headers, body, and matcher rules.
// - executor.rs: Implement zero-copy regex streaming evaluation against responses.
// - Integrate variables.rs to allow dynamic {{placeholder}} substitutions in requests.

pub mod executor;
