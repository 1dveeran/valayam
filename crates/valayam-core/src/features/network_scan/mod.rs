// TODO: Implement TCP/UDP Network Scanning (Phase 2).
// - parser.rs: Support port range syntax and banner matchers.
// - executor.rs: Implement concurrent TCP/UDP scanning with service identification,
//               version extraction, vulnerability assessment, and risk prioritization.
//               HTTP GET fallback for silent services is implemented in tcp::scan_ports.

pub mod executor;