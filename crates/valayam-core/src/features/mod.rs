// TODO: Implement Vertical Slices (Phases 1-30) as isolated features.
// - Ensure each module owns its parser, executor, and matcher logic without cross-dependencies.
// - Phase 1: http_scan, extractors, helpers.
// - Phase 2: network_scan, dns_audit, tls_audit.
// - Phase 3: scripting (Rhai engine), nuclei_compat.
// - Phase 5+: crawler, waf_detect, fuzzer, cloud_sec, iac_audit, etc.
// - Maintain strict downward dependency on core/ and network/ only.
pub mod dns_audit;
pub mod extractors;
pub mod helpers;
pub mod http_scan;
pub mod network_scan;
pub mod nuclei_compat;
pub mod scripting;
pub mod tls_audit;
pub mod crawler;
pub mod fuzzer;
pub mod waf_detect;
pub mod cloud_sec;
pub mod auth_logic;
pub mod deep_analysis;
pub mod iac_audit;
pub mod sbom_audit;
pub mod grpc_audit;
pub mod graphql_audit;
pub mod drift_detect;
pub mod cred_monitor;
pub mod oauth_audit;
pub mod idp_audit;
pub mod aws_escalate;
pub mod azure_gcp_escalate;
pub mod browser_audit;
pub mod iot_audit;
pub mod scada_audit;
pub mod auto_redteam;
pub mod implant_deploy;
pub mod client_secret_audit;
pub mod dom_redirect_audit;
pub mod cors_audit;
pub mod csp_audit;
pub mod waf_bypass_verify;
pub mod header_scorecard;
pub mod reputation_audit;
pub mod ct_log_audit;
pub mod remediation_gen;
pub mod mitre_mapping;
pub mod container_audit;
pub mod k8s_audit;
pub mod sast_taint;
pub mod sast_secrets;
pub mod subdomain_takeover;
pub mod port_scan;
pub mod schema_drift;
pub mod pii_leak_audit;
pub mod cicd_audit;
pub mod dependency_audit;
pub mod easm;
pub mod attack_graph;
pub mod web3_audit;
pub mod mobile_audit;
pub mod serverless_audit;
pub mod auto_exploit;
pub mod ui_proxy;
