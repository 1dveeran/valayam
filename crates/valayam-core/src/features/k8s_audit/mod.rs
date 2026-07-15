// TODO: Implement Kubernetes RBAC Auditing (Phase 26).
// - Manifest auditing for overly permissive roles and missing network policies.
// - Identify privileged pods and hostPath mounts.
// - Correlate RBAC findings to map potential cluster takeover paths.
pub mod parser;
pub mod executor;
