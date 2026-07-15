// TODO: Implement Cloud Metadata Exploitation (Phase 10).
// - Automated metadata discovery for AWS/GCP/Azure via SSRF.
// - Token harvesting via IMDSv2 challenge-response negotiation.
// - Validate and parse extracted IAM tokens for downstream privilege escalation.
pub mod parser;
pub mod executor;
