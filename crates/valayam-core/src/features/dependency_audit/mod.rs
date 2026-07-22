// TODO: Implement Dependency Chain Verification (Phase 30).
// - Lockfile analysis (Cargo.lock, package-lock.json) for known CVEs.
// - Native hook into the offline `vuln-db.sqlite` artifact for fast local checks.
// - Map transitive dependency vulnerabilities back to the root package.

pub mod executor;
pub mod extractor;
pub mod vuln_db;
