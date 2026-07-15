// TODO: Implement DNS Audit Scanning (Phase 2).
// - executor.rs: Support A, AAAA, CNAME, TXT, MX querying via hickory-resolver.
// - Add specific matchers for Subdomain Takeover and DNS Rebinding detection.
// - Implement AXFR zone transfer attempts as a fallback probe.
pub mod parser;
pub mod executor;
