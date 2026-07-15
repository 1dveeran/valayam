// TODO: Implement TCP/UDP Network Scanning (Phase 2).
// - parser.rs: Support port range syntax and banner matchers.
// - executor.rs: Implement concurrent TCP connect scanning and UDP probes.
// - Add HTTP GET fallback for silent services to capture banners.
pub mod parser;
pub mod executor;
