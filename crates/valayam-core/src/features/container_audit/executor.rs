// TODO: Expand Container Audit for enterprise deployments.
// - Integrate with Trivy/Grype for actual vulnerability scanning of image layers.
// - Add registry authentication support (Docker Hub, ECR, GCR, ACR, Harbor).
// - Implement Docker/containerd socket inspection for running containers.
// - Add OCI image manifest and layer analysis for hidden secrets.
// - Support SBOM generation and comparison against image layers.
// - Add CIS Docker Benchmark checks for running containers.
// - Implement multi-architecture image support (arm64, amd64, etc.).

use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use chrono::Utc;
use super::parser::ContainerAuditTemplate;

/// Container image audit configuration.
#[derive(Debug, Clone)]
pub struct ContainerAuditConfig {
    pub check_image_tag: bool,
    pub check_image_age: bool,
    pub check_registry: bool,
    pub check_exposed_ports: bool,
    pub check_volume_mounts: bool,
    pub check_env_vars: bool,
    pub check_entrypoint: bool,
    pub strict_mode: bool,
}

impl Default for ContainerAuditConfig {
    fn default() -> Self {
        Self {
            check_image_tag: true,
            check_image_age: true,
            check_registry: true,
            check_exposed_ports: true,
            check_volume_mounts: true,
            check_env_vars: true,
            check_entrypoint: true,
            strict_mode: true,
        }
    }
}

/// A single container audit finding.
#[derive(Debug, Clone)]
struct ContainerFinding {
    finding_type: &'static str,
    severity: &'static str,
    cvss_score: f32,
    message: String,
    solution: &'static str,
    reference: &'static str,
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "Critical" => 5,
        "High" => 4,
        "Medium" => 3,
        "Low" => 2,
        _ => 1,
    }
}

/// Known risky image registries.
const RISKY_REGISTRIES: &[&str] = &[
    "docker.io/unknown",
    "unknown.registry",
    "localhost",
    "192.168.",
    "10.",
    "172.16.",
];

/// Known vulnerable base image patterns.
const VULNERABLE_BASE_IMAGES: &[&str] = &[
    "ubuntu:18.04",
    "ubuntu:16.04",
    "centos:6",
    "centos:7",
    "debian:8",
    "debian:9",
    "alpine:3.12",
    "alpine:3.13",
    "alpine:3.14",
    "node:12",
    "node:14",
    "python:2.7",
    "python:3.6",
    "openjdk:8",
    "openjdk:11",
    "nginx:1.18",
    "nginx:1.19",
    "httpd:2.2",
    "httpd:2.4",
];

/// Known high-severity exposed ports for containers.
const DANGEROUS_EXPOSED_PORTS: &[(u16, &str, &str, f32)] = &[
    (22, "SSH port exposed", "High", 7.5),
    (23, "Telnet port exposed", "High", 7.0),
    (3389, "RDP port exposed", "High", 7.0),
    (5900, "VNC port exposed", "High", 7.0),
    (6379, "Redis port exposed (no auth)", "Medium", 6.0),
    (27017, "MongoDB port exposed", "Medium", 6.0),
    (5432, "PostgreSQL port exposed", "Low", 3.0),
    (3306, "MySQL port exposed", "Low", 3.0),
];

/// Check if an image tag indicates a risky pattern.
fn check_image_tag(image: &str, template_checks: &[String], config: &ContainerAuditConfig) -> Vec<ContainerFinding> {
    let mut findings = Vec::new();

    // Check for latest tag
    if image.ends_with(":latest") || !image.contains(':') {
        findings.push(ContainerFinding {
            finding_type: "latest_tag",
            severity: if config.strict_mode { "Medium" } else { "Low" },
            cvss_score: if config.strict_mode { 5.0 } else { 3.0 },
            message: format!(
                "Container image '{}' uses the 'latest' tag or no tag. \
                This can lead to unpredictable deployments and security drift.",
                image
            ),
            solution: "Pin images to a specific semantic version or digest (e.g., 'image:v1.2.3' or 'image@sha256:...'). Use automated dependency update tools.",
            reference: "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from",
        });
    }

    // Check for :latest + specific checks from template
    if template_checks.iter().any(|c| c == "no-latest") && (image.ends_with(":latest") || !image.contains(':')) {
        // Already handled above, just dedup
    }

    // Check for digest pinning
    if !image.contains('@') && config.strict_mode {
        findings.push(ContainerFinding {
            finding_type: "missing_digest",
            severity: "Low",
            cvss_score: 2.0,
            message: format!(
                "Image '{}' is not pinned to a digest (sha256). Tags are mutable and can be overwritten.",
                image
            ),
            solution: "Use image digest pinning: 'image@sha256:...' for immutable, verifiable deployments.",
            reference: "https://docs.docker.com/engine/reference/commandline/pull/#pull-an-image-by-digest-immutable-identifier",
        });
    }

    findings
}

/// Check the image registry for trustworthiness.
fn check_registry(image: &str) -> Vec<ContainerFinding> {
    let mut findings = Vec::new();

    // Extract registry from image name
    let registry = if image.contains('/') {
        image.split('/').next().unwrap_or("docker.io")
    } else {
        "docker.io"
    };

    // Check if registry is Docker Hub (requires more scrutiny)
    if registry == "docker.io" || registry == "index.docker.io" {
        // Docker Hub is legitimate but prone to squatting
        let parts: Vec<&str> = image.split('/').collect();
        if parts.len() >= 2 {
            let user_or_org = parts[if registry == image.split('/').next().unwrap() { 1 } else { 0 }];
            if user_or_org.len() == 1 || user_or_org.chars().all(|c| c.is_ascii_digit()) {
                findings.push(ContainerFinding {
                    finding_type: "suspicious_image_name",
                    severity: "Medium",
                    cvss_score: 5.0,
                    message: format!(
                        "Image '{}' from Docker Hub has a suspicious name segment '{}' \
                        which may indicate a squatting or typo-squatting attempt.",
                        image, user_or_org
                    ),
                    solution: "Verify the publisher of the image on Docker Hub. Use official images where possible. \
                        Consider using a private registry for production images.",
                    reference: "https://docs.docker.com/docker-hub/official_images/",
                });
            }
        }
    }

    // Check against risky registries
    for risky in RISKY_REGISTRIES {
        if registry.starts_with(risky) {
            findings.push(ContainerFinding {
                finding_type: "risky_registry",
                severity: "High",
                cvss_score: 7.0,
                message: format!(
                    "Image '{}' is from a potentially risky registry '{}'. \
                    Images from local/untrusted registries may contain vulnerabilities.",
                    image, registry
                ),
                solution: "Use trusted registries only. Pull images from official registries (Docker Hub official, \
                    ECR, GCR, ACR) with verified publishers.",
                reference: "https://docs.docker.com/engine/security/trust/",
            });
        }
    }

    // Check for implicit :latest
    if !image.contains(':') && registry != "docker.io" {
        findings.push(ContainerFinding {
            finding_type: "unstable_tag",
            severity: "Medium",
            cvss_score: 5.0,
            message: format!(
                "Image '{}' from non-Docker Hub registry has no explicit tag. \
                This may resolve to unpredictable versions depending on registry defaults.",
                image
            ),
            solution: "Always specify an explicit tag or digest when using non-default registries.",
            reference: "https://docs.docker.com/engine/reference/commandline/tag/",
        });
    }

    // Check for known EOL images
    for vulnerable in VULNERABLE_BASE_IMAGES {
        if image.contains(vulnerable) {
            findings.push(ContainerFinding {
                finding_type: "eol_base_image",
                severity: "High",
                cvss_score: 7.5,
                message: format!(
                    "Image '{}' uses '{}' which is end-of-life or has known critical vulnerabilities. \
                    This base image may no longer receive security patches.",
                    image, vulnerable
                ),
                solution: "Update to a supported version of the base image. Use distroless or \
                    minimal images (e.g., alpine:3.20+, distroless) for smaller attack surface.",
                reference: "https://endoflife.date/",
            });
        }
    }

    findings
}

/// Analyze exposed ports for security risks.
fn check_exposed_ports(ports: &[u16]) -> Vec<ContainerFinding> {
    let mut findings = Vec::new();

    for port in ports {
        for (dangerous_port, desc, severity, cvss) in DANGEROUS_EXPOSED_PORTS {
            if *port == *dangerous_port {
                findings.push(ContainerFinding {
                    finding_type: "dangerous_exposed_port",
                    severity,
                    cvss_score: *cvss,
                    message: format!(
                        "Container exposes port {} ({}) which is a common attack vector. \
                        Exposing management interfaces publicly increases attack surface.",
                        port, desc
                    ),
                    solution: "Do not expose management ports (SSH, RDP, Redis, DB) to external networks. \
                        Use internal networks and port forwarding for administration.",
                    reference: "https://docs.docker.com/network/",
                });
            }
        }
    }

    // Check for large number of exposed ports (attack surface)
    if ports.len() > 10 {
        findings.push(ContainerFinding {
            finding_type: "excessive_exposed_ports",
            severity: "Low",
            cvss_score: 3.0,
            message: format!(
                "Container exposes {} ports. A large number of exposed ports increases the attack surface.",
                ports.len()
            ),
            solution: "Only expose ports that are necessary for the application to function. \
                Use a reverse proxy for routing to internal applications.",
            reference: "https://docs.docker.com/config/containers/container-networking/",
        });
    }

    findings
}

/// Check environment variables for security issues.
fn check_env_vars(env: &[(String, String)]) -> Vec<ContainerFinding> {
    let mut findings = Vec::new();
    let sensitive_keys = ["PASSWORD", "SECRET", "API_KEY", "TOKEN", "CREDENTIAL",
        "ACCESS_KEY", "SECRET_KEY", "PRIVATE_KEY", "AUTH", "PASSWD"];

    for (key, value) in env {
        let upper_key = key.to_uppercase();
        for sensitive in &sensitive_keys {
            if upper_key.contains(sensitive) && !value.is_empty() {
                findings.push(ContainerFinding {
                    finding_type: "sensitive_env_var",
                    severity: "High",
                    cvss_score: 7.5,
                    message: format!(
                        "Environment variable '{}' appears to contain sensitive data ({}-length value). \
                        Secrets in environment variables can leak through 'docker inspect', logs, and debug endpoints.",
                        key, value.len()
                    ),
                    solution: "Use Docker secrets, Kubernetes Secrets, or a vault solution \
                        (HashiCorp Vault, AWS Secrets Manager) for sensitive data. \
                        Avoid hardcoding secrets in environment variables.",
                    reference: "https://docs.docker.com/engine/swarm/secrets/",
                });
                break;
            }
        }

        // Check for empty critical vars
        if value.is_empty() && upper_key.contains("PASSWORD") {
            findings.push(ContainerFinding {
                finding_type: "empty_password_var",
                severity: "Medium",
                cvss_score: 5.0,
                message: format!(
                    "Environment variable '{}' is set to an empty value. \
                    An empty password may allow unauthenticated access.",
                    key
                ),
                solution: "Ensure all authentication-related environment variables have proper non-empty values. \
                    Consider using secrets management instead.",
                reference: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            });
        }
    }

    findings
}

/// Parse the checks list and run applicable validations.
fn run_checks(
    image: &str,
    checks: &[String],
    config: &ContainerAuditConfig,
) -> Vec<ContainerFinding> {
    let mut all_findings = Vec::new();

    // Image tag checks
    if config.check_image_tag {
        all_findings.extend(check_image_tag(image, checks, config));
    }

    // Registry checks
    if config.check_registry {
        all_findings.extend(check_registry(image));
    }

    // Import known port data from the checks list
    if config.check_exposed_ports {
        let ports: Vec<u16> = checks.iter()
            .filter_map(|c| {
                if let Some(port_str) = c.strip_prefix("port:") {
                    port_str.parse::<u16>().ok()
                } else {
                    None
                }
            })
            .collect();
        if !ports.is_empty() {
            all_findings.extend(check_exposed_ports(&ports));
        }
    }

    // Environment variable checks
    if config.check_env_vars {
        let env_vars: Vec<(String, String)> = checks.iter()
            .filter_map(|c| {
                if let Some(env_str) = c.strip_prefix("env:") {
                    let parts: Vec<&str> = env_str.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        Some((parts[0].to_string(), parts[1].to_string()))
                    } else {
                        Some((parts[0].to_string(), String::new()))
                    }
                } else {
                    None
                }
            })
            .collect();
        if !env_vars.is_empty() {
            all_findings.extend(check_env_vars(&env_vars));
        }
    }

    // EOL image check
    if checks.iter().any(|c| c == "check-eol" || c == "eol") {
        for vulnerable in VULNERABLE_BASE_IMAGES {
            if image.contains(vulnerable) {
                // Check if we already flagged this from registry check
                if !all_findings.iter().any(|f| f.finding_type == "eol_base_image" && f.message.contains(vulnerable)) {
                    all_findings.push(ContainerFinding {
                        finding_type: "eol_base_image",
                        severity: "High",
                        cvss_score: 7.5,
                        message: format!(
                            "Image '{}' matches known EOL/vulnerable base '{}'.",
                            image, vulnerable
                        ),
                        solution: "Update base image to a supported version.",
                        reference: "https://endoflife.date/",
                    });
                }
            }
        }
    }

    all_findings
}

/// Aggregate findings into a ScanResult.
fn aggregate_container_findings(
    all_findings: Vec<ContainerFinding>,
    image: &str,
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    if all_findings.is_empty() {
        return Some(ScanResult {
            timestamp: Utc::now(),
            template_id: template_id.to_string(),
            template_name: template_info.name.clone(),
            template_severity: "Info".to_string(),
            target: image.to_string(),
            payload: format!("Container Audit: No security issues found for image '{}'.", image),
            cvss_score: Some(0.0),
            reference: Some("https://docs.docker.com/engine/security/".to_string()),
            solution: None,
            tags: vec!["container".to_string(), "audit".to_string(), "clean".to_string()],
            compliance: Default::default(),
        });
    }

    let worst = all_findings.iter()
        .max_by_key(|f| severity_rank(f.severity))
        .unwrap();

    let worst_cvss = all_findings.iter()
        .map(|f| f.cvss_score)
        .fold(0.0f32, f32::max);

    let details: Vec<String> = all_findings.iter()
        .map(|f| format!("[{}][{:.1}] {}", f.severity, f.cvss_score, f.message))
        .collect();

    let solution_text: Vec<String> = all_findings.iter()
        .map(|f| f.solution.to_string())
        .collect();

    let finding_tags: Vec<String> = all_findings.iter()
        .map(|f| format!("container:{}:{}", f.finding_type, f.severity.to_lowercase()))
        .collect();

    Some(ScanResult {
        timestamp: Utc::now(),
        template_id: template_id.to_string(),
        template_name: template_info.name.clone(),
        template_severity: worst.severity.to_string(),
        target: image.to_string(),
        payload: format!(
            "Container Audit Report for '{}': {} issue(s) found.\n- {}",
            image,
            all_findings.len(),
            details.join("\n- "),
        ),
        cvss_score: Some(worst_cvss),
        reference: Some("https://docs.docker.com/engine/security/".to_string()),
        solution: Some(format!(
            "Remediation steps:\n- {}",
            solution_text.join("\n- "),
        )),
        tags: {
            let mut t = vec![
                "container".to_string(),
                "audit".to_string(),
                format!("issues:{}", all_findings.len()),
            ];
            t.extend(finding_tags);
            t
        },
        compliance: Default::default(),
    })
}

/// Main container audit executor.
pub async fn execute(
    templates: &[ContainerAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    let config = ContainerAuditConfig::default();

    if let Some(template) = templates.iter().next() {
        let image = &template.target_image;
        let checks = &template.checks;

        let all_findings = run_checks(image, checks, &config);

        return aggregate_container_findings(all_findings, image, template_id, template_info);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latest_tag_detection() {
        let findings = check_image_tag("nginx:latest", &[], &ContainerAuditConfig::default());
        assert!(findings.iter().any(|f| f.finding_type == "latest_tag"));
    }

    #[test]
    fn test_no_tag_also_detected() {
        let findings = check_image_tag("myapp", &[], &ContainerAuditConfig::default());
        assert!(findings.iter().any(|f| f.finding_type == "latest_tag"));
    }

    #[test]
    fn test_pinned_version_no_finding() {
        let findings = check_image_tag("nginx:1.24.0", &[], &ContainerAuditConfig::default());
        // No "latest_tag" finding
        assert!(!findings.iter().any(|f| f.finding_type == "latest_tag"));
    }

    #[test]
    fn test_suspicious_image_name() {
        let findings = check_registry("docker.io/a/a");
        assert!(findings.iter().any(|f| f.finding_type == "suspicious_image_name"));
    }

    #[test]
    fn test_vulnerable_base_image() {
        let findings = check_registry("ubuntu:18.04");
        assert!(findings.iter().any(|f| f.finding_type == "eol_base_image"));
    }

    #[test]
    fn test_dangerous_exposed_port() {
        let findings = check_exposed_ports(&[22]);
        assert!(findings.iter().any(|f| f.finding_type == "dangerous_exposed_port"));
    }

    #[test]
    fn test_safe_ports_no_finding() {
        let findings = check_exposed_ports(&[8080, 443, 3000]);
        assert!(!findings.iter().any(|f| f.finding_type == "dangerous_exposed_port"));
    }

    #[test]
    fn test_sensitive_env_var_detection() {
        let env = vec![("DB_PASSWORD".to_string(), "supersecret123".to_string())];
        let findings = check_env_vars(&env);
        assert!(findings.iter().any(|f| f.finding_type == "sensitive_env_var"));
    }

    #[test]
    fn test_excessive_ports() {
        let ports: Vec<u16> = (1..=15).collect();
        let findings = check_exposed_ports(&ports);
        assert!(findings.iter().any(|f| f.finding_type == "excessive_exposed_ports"));
    }

    #[test]
    fn test_aggregate_empty_no_findings() {
        let result = aggregate_container_findings(vec![], "nginx:latest", "test", &TemplateInfo::default());
        assert!(result.is_some());
        assert_eq!(result.unwrap().template_severity, "Info");
    }

    #[test]
    fn test_aggregate_with_findings() {
        let findings = vec![ContainerFinding {
            finding_type: "latest_tag",
            severity: "Medium",
            cvss_score: 5.0,
            message: "test finding".to_string(),
            solution: "Pin to specific version.",
            reference: "https://test.com",
        }];
        let result = aggregate_container_findings(findings, "test:latest", "test", &TemplateInfo::default());
        assert!(result.is_some());
        assert_eq!(result.unwrap().template_severity, "Medium");
    }
}