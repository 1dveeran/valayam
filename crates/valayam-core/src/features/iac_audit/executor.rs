// TODO: Expand IaC Audit for enterprise deployments.
// - Add CloudFormation template parsing with full resource enumeration.
// - Integrate with Open Policy Agent (OPA) Rego policies for custom rules.
// - Add Pulumi and CDKTF (CDK for Terraform) support.
// - Implement `terraform plan` JSON output parsing for pre-deployment checks.
// - Add CIS Benchmark checks for Terraform configurations.
// - Support remote state backends (S3, GCS, Azure) for policy-as-code gate checks.

use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use chrono::Utc;
use std::fs;
use std::path::Path;
use super::parser::IacAuditTemplate;

/// Configuration for IaC audit checks.
#[derive(Debug, Clone)]
pub struct IacAuditConfig {
    pub check_terraform: bool,
    pub check_dockerfile: bool,
    pub check_cloudformation: bool,
    pub check_kustomize: bool,
    pub check_helm: bool,
    pub strict_mode: bool,
    pub max_cidr_prefix: u8,
}

impl Default for IacAuditConfig {
    fn default() -> Self {
        Self {
            check_terraform: true,
            check_dockerfile: true,
            check_cloudformation: true,
            check_kustomize: true,
            check_helm: true,
            strict_mode: true,
            max_cidr_prefix: 24,
        }
    }
}

/// A single IaC finding.
#[derive(Debug, Clone)]
struct IacFinding {
    finding_type: &'static str,
    severity: &'static str,
    cvss_score: f32,
    message: String,
    solution: &'static str,
    reference: &'static str,
    line_number: Option<usize>,
}

/// Known dangerous Terraform patterns (regex patterns in plain text).
const TERRAFORM_DANGEROUS_PATTERNS: &[(&str, &str, &str, f32, &str, &str)] = &[
    // CIDR: overly permissive
    ("0.0.0.0/0", "overly_permissive_cidr", "Critical", 9.0,
     "Replace 0.0.0.0/0 with a specific IP range or use a VPC with proper security groups.",
     "https://owasp.org/www-community/attacks/Security_Misconfiguration"),
    // Public S3 ACL
    ("acl.*public-read", "public_s3_acl", "High", 8.0,
     "Remove public-read ACL and use bucket policies with least-privilege access.",
     "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"),
    ("acl.*public-read-write", "public_s3_acl_write", "Critical", 9.5,
     "Remove public-read-write ACL immediately. Bucket contents can be read and modified by anyone.",
     "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"),
    // IAM: full admin access
    ("\"*\"", "iam_full_admin", "Critical", 9.0,
     "Restrict IAM policy to specific actions and resources. Avoid using '*' in Action or Resource.",
     "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"),
    // EBS/S3/GCS bucket encryption disabled
    ("server_side_encryption_configuration", "missing_encryption", "Medium", 5.0,
     "Enable server-side encryption for all data storage resources.",
     "https://docs.aws.amazon.com/kms/latest/developerguide/services-s3.html"),
    // RDS: publicly accessible
    ("publicly_accessible.*true", "public_rds", "High", 7.5,
     "Set publicly_accessible to false for RDS instances. Use a VPC with private subnets.",
     "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html"),
    // SSH keys in metadata
    ("ssh_authorized_keys", "ssh_key_in_metadata", "High", 7.0,
     "Do not embed SSH keys in instance metadata. Use a proper key management solution.",
     "https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys"),
    // HTTP (not HTTPS) load balancer
    ("http.*listener.*80", "http_listener", "Medium", 5.5,
     "Use HTTPS listeners (port 443) with TLS certificates instead of HTTP.",
     "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html"),
];

/// Dockerfile security check patterns.
const DOCKERFILE_CHECKS: &[(&str, &str, &str, f32, &str, &str)] = &[
    ("USER root", "container_as_root", "High", 7.0,
     "Add a non-root USER directive. Use a distroless base image where possible.",
     "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"),
    ("ADD", "add_instead_of_copy", "Medium", 4.0,
     "Use COPY instead of ADD unless you need automatic tar extraction or URL download.",
     "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy"),
    ("EXPOSE 22", "ssh_port_exposed", "High", 7.5,
     "Do not expose SSH port. If SSH access is needed, use a bastion host or VPN.",
     "https://docs.docker.com/engine/reference/builder/#expose"),
    (":latest", "latest_tag", "Low", 3.0,
     "Pin base image to a specific version tag instead of 'latest' for reproducible builds.",
     "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from"),
    ("ENV.*PASSWORD", "password_in_env", "Critical", 9.0,
     "Never store passwords or secrets in environment variables in Dockerfiles. Use secrets management.",
     "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#env"),
    ("ENV.*SECRET", "secret_in_env", "Critical", 9.0,
     "Never store secrets in environment variables in Dockerfiles. Use Docker secrets or a vault.",
     "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#env"),
    ("ENV.*API_KEY", "apikey_in_env", "Critical", 9.0,
     "Never store API keys in Dockerfiles. Use build args with proper secret mounting.",
     "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#env"),
    ("apt-get.*install.*-y", "unpinned_package", "Medium", 5.0,
     "Pin package versions in apt-get install to ensure reproducible builds.",
     "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#apt-get"),
    ("apt-get update", "missing_cleanup", "Medium", 4.0,
     "Combine apt-get update and install in the same RUN layer, and clean up cache with rm -rf /var/lib/apt/lists/*.",
     "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#apt-get"),
];

/// CloudFormation dangerous patterns.
const CFN_DANGEROUS_PATTERNS: &[(&str, &str, &str, f32, &str, &str)] = &[
    ("AWS::IAM::Role.*ManagedPolicyArns.*AdministratorAccess", "cfn_admin_role", "Critical", 9.0,
     "Avoid attaching AdministratorAccess managed policy. Create scoped-down custom policies.",
     "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"),
    ("AWS::EC2::SecurityGroup", "cfn_open_sg", "Critical", 9.5,
     "Do not use 0.0.0.0/0 in security group ingress rules. Restrict to specific IP ranges.",
     "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"),
    ("AWS::S3::Bucket.*PublicAccessBlockConfiguration.*false", "cfn_public_s3", "High", 8.0,
     "Enable public access block on S3 buckets to prevent accidental data exposure.",
     "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"),
];

/// Check Terraform content for security issues.
fn check_terraform(content: &str, _config: &IacAuditConfig) -> Vec<IacFinding> {
    let mut findings = Vec::new();

    for (pattern, finding_type, severity, cvss, solution, reference) in TERRAFORM_DANGEROUS_PATTERNS {
        // Use simple substring matching (pattern is already a plain text fragment)
        if let Some(line) = content.lines().position(|l| l.contains(pattern)) {
            findings.push(IacFinding {
                finding_type,
                severity,
                cvss_score: *cvss,
                message: format!(
                    "Dangerous Terraform pattern '{}' found at line {}. This indicates {}.",
                    pattern, line + 1,
                    match *finding_type {
                        "overly_permissive_cidr" => "an overly permissive network access rule",
                        "public_s3_acl" => "a publicly readable S3 bucket",
                        "public_s3_acl_write" => "a publicly writable S3 bucket",
                        "iam_full_admin" => "a full administrative access IAM policy",
                        "missing_encryption" => "encryption is not configured",
                        "public_rds" => "a publicly accessible database instance",
                        "ssh_key_in_metadata" => "SSH keys embedded in metadata",
                        "http_listener" => "HTTP (unencrypted) listener is used",
                        _ => "a security misconfiguration",
                    },
                ),
                solution,
                reference,
                line_number: Some(line + 1),
            });
        }
    }

    // Check for tfsec/checkov ignore comments
    if content.contains("tfsec:ignore") {
        findings.push(IacFinding {
            finding_type: "tfsec_ignore",
            severity: "Info",
            cvss_score: 0.0,
            message: "Found 'tfsec:ignore' comments in Terraform file. Review each suppressed rule to ensure it is intentional and documented.".to_string(),
            solution: "Document each suppression with a reason and expiration date. Use centralized policy exceptions.",
            reference: "https://github.com/aquasecurity/tfsec",
            line_number: None,
        });
    }

    findings
}

/// Check Dockerfile content for security issues.
fn check_dockerfile(content: &str, _config: &IacAuditConfig) -> Vec<IacFinding> {
    let mut findings = Vec::new();

    for (pattern, finding_type, severity, cvss, solution, reference) in DOCKERFILE_CHECKS {
        if let Some(line) = content.lines().position(|l| l.contains(pattern)) {
            findings.push(IacFinding {
                finding_type,
                severity,
                cvss_score: *cvss,
                message: format!(
                    "Dockerfile security issue '{}' found at line {}: pattern '{}'.",
                    finding_type, line + 1, pattern
                ),
                solution,
                reference,
                line_number: Some(line + 1),
            });
        }
    }

    // Check for multi-stage build
    if !content.contains("FROM.* AS ") && !content.contains("FROM.* as ") {
        if let Ok(re) = regex::Regex::new(r"(?m)^FROM\s+\S+") {
            let from_count = re.find_iter(content).count();
            if from_count == 1 {
                findings.push(IacFinding {
                    finding_type: "no_multi_stage",
                    severity: "Low",
                    cvss_score: 2.0,
                    message: "Dockerfile uses a single-stage build. Multi-stage builds reduce image size and attack surface.".to_string(),
                    solution: "Use multi-stage builds: builder stage for compilation and a minimal runtime stage for the final image.",
                    reference: "https://docs.docker.com/develop/develop-images/multistage-build/",
                    line_number: None,
                });
            }
        }
    }

    // Check for HEALTHCHECK
    if !content.contains("HEALTHCHECK") {
        findings.push(IacFinding {
            finding_type: "missing_healthcheck",
            severity: "Low",
            cvss_score: 2.5,
            message: "Dockerfile is missing a HEALTHCHECK instruction. HEALTHCHECK enables Docker to detect and restart unhealthy containers.".to_string(),
            solution: "Add a HEALTHCHECK instruction with a curl or custom health check command.",
            reference: "https://docs.docker.com/engine/reference/builder/#healthcheck",
            line_number: None,
        });
    }

    findings
}

/// Check CloudFormation content for security issues.
fn check_cloudformation(content: &str, _config: &IacAuditConfig) -> Vec<IacFinding> {
    let mut findings = Vec::new();

    for (pattern, finding_type, severity, cvss, solution, reference) in CFN_DANGEROUS_PATTERNS {
        if content.contains(pattern) {
            findings.push(IacFinding {
                finding_type,
                severity,
                cvss_score: *cvss,
                message: format!(
                    "CloudFormation security issue '{}' detected. Pattern '{}' indicates a misconfiguration.",
                    finding_type, pattern
                ),
                solution,
                reference,
                line_number: None,
            });
        }
    }

    // Check for missing DeletionPolicy
    if content.contains("AWS::S3::Bucket") && !content.contains("DeletionPolicy") {
        findings.push(IacFinding {
            finding_type: "missing_deletion_policy",
            severity: "Medium",
            cvss_score: 5.0,
            message: "S3 Bucket resource found without DeletionPolicy. Stack deletion could result in data loss.".to_string(),
            solution: "Add DeletionPolicy: Retain to S3 buckets and other data-critical resources.",
            reference: "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-deletionpolicy.html",
            line_number: None,
        });
    }

    findings
}

/// Aggregate findings into a single ScanResult.
fn aggregate_findings(
    all_findings: &[IacFinding],
    target: &str,
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    if all_findings.is_empty() {
        return Some(ScanResult {
            timestamp: Utc::now(),
            template_id: template_id.to_string(),
            template_name: template_info.name.clone(),
            template_severity: "Info".to_string(),
            target: target.to_string(),
            payload: format!("IaC Audit: No security issues found in '{}'.", target),
            cvss_score: Some(0.0),
            reference: Some("https://owasp.org/www-community/Infrastructure_as_Code_Security".to_string()),
            solution: None,
            tags: vec!["iac".to_string(), "audit".to_string(), "clean".to_string()],
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
        .map(|f| format!("[{}][{:.1}] {} (line {})",
            f.severity, f.cvss_score, f.message,
            f.line_number.map(|l| l.to_string()).unwrap_or_else(|| "N/A".to_string())
        ))
        .collect();

    let solution_lines: Vec<String> = all_findings.iter()
        .map(|f| f.solution.to_string())
        .collect();

    let finding_types: Vec<String> = all_findings.iter()
        .map(|f| format!("iac:{}:{}", f.finding_type, f.severity.to_lowercase()))
        .collect();

    Some(ScanResult {
        timestamp: Utc::now(),
        template_id: template_id.to_string(),
        template_name: template_info.name.clone(),
        template_severity: worst.severity.to_string(),
        target: target.to_string(),
        payload: format!(
            "IaC Audit Report for '{}': {} issue(s) found.\n- {}",
            target,
            all_findings.len(),
            details.join("\n- "),
        ),
        cvss_score: Some(worst_cvss),
        reference: Some("https://owasp.org/www-community/Infrastructure_as_Code_Security".to_string()),
        solution: Some(format!(
            "Remediation steps:\n- {}",
            solution_lines.join("\n- "),
        )),
        tags: {
            let mut t = vec!["iac".to_string(), "audit".to_string(), format!("issues:{}", all_findings.len())];
            t.extend(finding_types);
            t
        },
        compliance: Default::default(),
    })
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

/// Main IaC audit executor.
pub async fn execute(
    templates: &[IacAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    let config = IacAuditConfig::default();

    for template in templates {
        let path = Path::new(&template.target);
        if !path.exists() {
            continue;
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(target = %template.target, error = %e, "IaC audit: failed to read file");
                continue;
            }
        };

        let mut all_findings: Vec<IacFinding> = Vec::new();

        // Check based on type
        match template.r#type.as_str() {
            "terraform" if config.check_terraform => {
                all_findings = check_terraform(&content, &config);
            }
            "docker" | "dockerfile" if config.check_dockerfile => {
                all_findings = check_dockerfile(&content, &config);
            }
            "cloudformation" | "cfn" if config.check_cloudformation => {
                all_findings = check_cloudformation(&content, &config);
            }
            "auto" | "all" => {
                all_findings.extend(check_terraform(&content, &config));
                all_findings.extend(check_dockerfile(&content, &config));
                all_findings.extend(check_cloudformation(&content, &config));
            }
            _ => {
                // Unknown type — do generic checks (terraform patterns are the broadest)
                all_findings.extend(check_terraform(&content, &config));
            }
        }

        return aggregate_findings(&all_findings, &template.target, template_id, template_info);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terraform_overly_permissive_cidr() {
        let content = r#"
resource "aws_security_group" "public" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}"#;
        let findings = check_terraform(content, &IacAuditConfig::default());
        assert!(findings.iter().any(|f| f.finding_type == "overly_permissive_cidr"));
    }

    #[test]
    fn test_terraform_iam_admin() {
        let content = r#"
resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Action = "*"
    Effect = "Allow"
  })
}"#;
        let findings = check_terraform(content, &IacAuditConfig::default());
        assert!(findings.iter().any(|f| f.finding_type == "iam_full_admin"));
    }

    #[test]
    fn test_dockerfile_root_user() {
        let content = "FROM ubuntu:latest\nRUN apt-get update\nUSER root";
        let findings = check_dockerfile(content, &IacAuditConfig::default());
        assert!(findings.iter().any(|f| f.finding_type == "container_as_root"));
    }

    #[test]
    fn test_dockerfile_add_warning() {
        let content = "FROM alpine:3.18\nADD script.sh /opt/\nUSER appuser";
        let findings = check_dockerfile(content, &IacAuditConfig::default());
        assert!(findings.iter().any(|f| f.finding_type == "add_instead_of_copy"));
    }

    #[test]
    fn test_dockerfile_healthcheck_missing() {
        let content = "FROM alpine:3.18\nRUN apk add curl\nCOPY app /app\nENTRYPOINT [\"/app\"]";
        let findings = check_dockerfile(content, &IacAuditConfig::default());
        assert!(findings.iter().any(|f| f.finding_type == "missing_healthcheck"));
    }

    #[test]
    fn test_cloudformation_open_sg() {
        let content = r#"
Resources:
  PublicSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: "Open SG"
      SecurityGroupIngress:
        - CidrIp: 0.0.0.0/0"#;
        let findings = check_cloudformation(content, &IacAuditConfig::default());
        assert!(findings.iter().any(|f| f.finding_type == "cfn_open_sg"));
    }

    #[test]
    fn test_dockerfile_latest_tag() {
        let content = "FROM node:latest\nUSER node\nCOPY . /app\nHEALTHCHECK curl -f http://localhost/";
        let findings = check_dockerfile(content, &IacAuditConfig::default());
        assert!(findings.iter().any(|f| f.finding_type == "latest_tag"));
    }

    #[test]
    fn test_aggregate_empty() {
        let result = aggregate_findings(&[], "test.tf", "test", &TemplateInfo::default());
        assert!(result.is_some());
        assert_eq!(result.unwrap().template_severity, "Info");
    }

    #[test]
    fn test_tfsec_ignore_detected() {
        let content = "resource \"aws_s3_bucket\" \"x\" {\n  # tfsec:ignore:aws-s3-block-public-access\n}";
        let findings = check_terraform(content, &IacAuditConfig::default());
        assert!(findings.iter().any(|f| f.finding_type == "tfsec_ignore"));
    }
}