// TODO: Implement AWS IAM Privilege Escalation (Phase 17).
// - Automated STS and IAM permission enumeration (sts:GetCallerIdentity).
// - Lateral movement vectors via updating Lambda code or passing roles to EC2.
// - Graph out escalation paths using the extracted IAM policies.
pub mod parser;
pub mod executor;
