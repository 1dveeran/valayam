// TODO: Implement Vertical Slices (Phases 1-30) as isolated features.
// - Ensure each module owns its parser, executor, and matcher logic without cross-dependencies.
// - Phase 1: http_scan
// - Phase 2: network_scan, dns_audit
// - Phase 5+: crawler, cloud_sec, iac_audit, etc.
// - Maintain strict downward dependency on core/ and network/ only.

pub mod extractors;
pub mod helpers;
pub mod http_scan;
pub mod crawler;
pub mod schema_drift;
pub mod threat_intel;
pub mod ui_proxy;
