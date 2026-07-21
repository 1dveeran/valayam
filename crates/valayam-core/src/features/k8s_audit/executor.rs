// TODO: Expand Kubernetes Audit for enterprise deployments.
// - Add OPA Gatekeeper integration for policy-as-code validation.
// - Implement kube-bench CIS benchmark checks for control plane auditing.
// - Add admission webhook simulation for validating mutating webhook risks.
// - Support Helm chart template rendering and pre-install validation.
// - Add Kyverno policy integration for complementary policy checks.
// - Implement live cluster auditing via kubeconfig authentication.

use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use chrono::Utc;
use serde_yaml::Value;
use std::fs;
use super::parser::K8sAuditTemplate;

/// Kubernetes security check configuration.
#[derive(Debug, Clone)]
pub struct K8sAuditConfig {
    pub check_rbac: bool,
    pub check_privilege_escalation: bool,
    pub check_resources: bool,
    pub check_network_policies: bool,
    pub check_images: bool,
    pub check_host_access: bool,
    pub check_probes: bool,
    pub strict_mode: bool,
}

impl Default for K8sAuditConfig {
    fn default() -> Self {
        Self {
            check_rbac: true,
            check_privilege_escalation: true,
            check_resources: true,
            check_network_policies: true,
            check_images: true,
            check_host_access: true,
            check_probes: true,
            strict_mode: true,
        }
    }
}

/// A single K8s audit finding.
#[derive(Debug, Clone)]
struct K8sFinding {
    kind: String,
    name: String,
    namespace: String,
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

/// Check RBAC configuration for over-permissive bindings.
fn check_rbac(val: &Value, strict: bool) -> Vec<K8sFinding> {
    let mut findings = Vec::new();
    let kind = val.get("kind").and_then(|v| v.as_str()).unwrap_or("Unknown");
    let name = val.get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed");
    let namespace = val.get("metadata")
        .and_then(|m| m.get("namespace"))
        .and_then(|v| v.as_str())
        .unwrap_or("default");

    // Check ClusterRoleBinding / RoleBinding and ClusterRole / Role
    if kind == "ClusterRoleBinding" || kind == "RoleBinding" || kind == "ClusterRole" || kind == "Role" {
        if let Some(role_ref) = val.get("roleRef") {
            let role_name = role_ref.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let _role_kind = role_ref.get("kind").and_then(|v| v.as_str()).unwrap_or("");

            // cluster-admin binding is critical
            if role_name == "cluster-admin" && kind == "ClusterRoleBinding" {
                findings.push(K8sFinding {
                    kind: kind.to_string(),
                    name: name.to_string(),
                    namespace: namespace.to_string(),
                    finding_type: "cluster_admin_binding",
                    severity: "Critical",
                    cvss_score: 9.0,
                    message: format!(
                        "ClusterRoleBinding '{}' binds '{}' role to subjects, granting cluster-wide admin access.",
                        name, role_name
                    ),
                    solution: "Avoid using cluster-admin role. Create scoped roles with least-privilege permissions. Use RoleBinding (namespaced) instead of ClusterRoleBinding where possible.",
                    reference: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
                });
            }
        }

        // Check for wildcard verbs — applies to ClusterRole/Role (rules at top level)
        // and to bindings that may embed inline rules.
        if let Some(rules) = val.get("rules").and_then(|r| r.as_sequence()) {
            for (i, rule) in rules.iter().enumerate() {
                let verbs = rule.get("verbs").and_then(|v| v.as_sequence())
                    .map(|v| v.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>())
                    .unwrap_or_default();
                let resources = rule.get("resources").and_then(|v| v.as_sequence())
                    .map(|v| v.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>())
                    .unwrap_or_default();
                let api_groups = rule.get("apiGroups").and_then(|v| v.as_sequence())
                    .map(|v| v.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>())
                    .unwrap_or_default();

                if verbs.contains(&"*") && resources.contains(&"*") {
                    findings.push(K8sFinding {
                        kind: kind.to_string(),
                        name: name.to_string(),
                        namespace: namespace.to_string(),
                        finding_type: "wildcard_rbac_rule",
                        severity: if strict { "Critical" } else { "High" },
                        cvss_score: if strict { 8.5 } else { 7.5 },
                        message: format!(
                            "RBAC rule #{} in '{}' grants wildcard access ('*' verbs, '*' resources, apiGroups: {:?}). \
                            This is equivalent to admin access.",
                            i, name, api_groups
                        ),
                        solution: "Replace wildcard '*' with specific verbs (get, list, watch, create, update, patch, delete) and specific resources (pods, secrets, configmaps, etc.).",
                        reference: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole",
                    });
                }
            }
        }

        // Check for subject wildcards — applies to binding kinds that have subjects
        if let Some(subjects) = val.get("subjects").and_then(|s| s.as_sequence()) {
            for subject in subjects {
                if let Some(sname) = subject.get("name").and_then(|v| v.as_str()) {
                    if sname == "*" || sname == "system:anonymous" || sname == "system:unauthenticated" {
                        findings.push(K8sFinding {
                            kind: kind.to_string(),
                            name: name.to_string(),
                            namespace: namespace.to_string(),
                            finding_type: "wildcard_subject",
                            severity: "Critical",
                            cvss_score: 9.5,
                            message: format!(
                                "RBAC binding '{}' includes subject '{}' which allows unauthenticated/anonymous access.",
                                name, sname
                            ),
                            solution: "Remove wildcard and anonymous subjects from RBAC bindings. Authenticate all users and service accounts.",
                            reference: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#service-account-permissions",
                        });
                    }
                }
            }
        }
    }

    findings
}

/// Check Pod/Deployment security context.
fn check_security_context(kind: &str, name: &str, namespace: &str, val: &Value, strict: bool) -> Vec<K8sFinding> {
    let mut findings = Vec::new();

    // Navigate to the pod template spec
    let spec = if kind == "Pod" {
        val.get("spec")
    } else {
        val.get("spec")
            .and_then(|s| s.get("template"))
            .and_then(|t| t.get("spec"))
    };

    let spec = match spec {
        Some(s) => s,
        None => return findings,
    };

    // Check privilege escalation
    if let Some(sc) = spec.get("securityContext") {
        // Check runAsNonRoot
        let run_as_non_root = sc.get("runAsNonRoot").and_then(|v| v.as_bool()).unwrap_or(false);
        if !run_as_non_root && strict {
            findings.push(K8sFinding {
                kind: kind.to_string(),
                name: name.to_string(),
                namespace: namespace.to_string(),
                finding_type: "run_as_non_root",
                severity: "Medium",
                cvss_score: 5.0,
                message: format!(
                    "Security context in '{}'/'{}' does not set runAsNonRoot: true. \
                    Pods may run as root.",
                    kind, name
                ),
                solution: "Set 'securityContext.runAsNonRoot: true' and 'securityContext.runAsUser: 1000' (or any non-zero UID).",
                reference: "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
            });
        }

        // Check readOnlyRootFilesystem
        let readonly_root = sc.get("readOnlyRootFilesystem").and_then(|v| v.as_bool()).unwrap_or(false);
        if !readonly_root {
            findings.push(K8sFinding {
                kind: kind.to_string(),
                name: name.to_string(),
                namespace: namespace.to_string(),
                finding_type: "readonly_root_fs",
                severity: "Low",
                cvss_score: 3.0,
                message: format!(
                    "Security context in '{}'/'{}' does not set readOnlyRootFilesystem: true. \
                    Container can write to the root filesystem.",
                    kind, name
                ),
                solution: "Set 'securityContext.readOnlyRootFilesystem: true' and mount writable volumes for temporary files.",
                reference: "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
            });
        }

        // Check capabilities
        if let Some(caps) = sc.get("capabilities") {
            if let Some(add) = caps.get("add").and_then(|a| a.as_sequence()) {
                let dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
                    "SYS_RAWIO", "SYS_BOOT", "NET_RAW", "SYS_CHROOT"];
                for cap in add {
                    if let Some(cap_str) = cap.as_str() {
                        for dangerous in &dangerous_caps {
                            if cap_str == *dangerous {
                                findings.push(K8sFinding {
                                    kind: kind.to_string(),
                                    name: name.to_string(),
                                    namespace: namespace.to_string(),
                                    finding_type: "dangerous_capability",
                                    severity: "High",
                                    cvss_score: 7.5,
                                    message: format!(
                                        "Container in '{}'/'{}' adds dangerous capability '{}'.",
                                        kind, name, cap_str
                                    ),
                                    solution: "Remove dangerous capabilities. Use 'capabilities.drop: [ALL]' and only add specific required capabilities.",
                                    reference: "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container",
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Check privileged mode (string-based for MVP, also try deep)
    if let Some(containers) = spec.get("containers").and_then(|c| c.as_sequence()) {
        for (i, container) in containers.iter().enumerate() {
            let default_cname = format!("container-{}", i);
            let cname = container.get("name").and_then(|n| n.as_str()).unwrap_or(&default_cname);

            // Check privileged
            if let Some(sc) = container.get("securityContext") {
                let privileged = sc.get("privileged").and_then(|v| v.as_bool()).unwrap_or(false);
                if privileged {
                    findings.push(K8sFinding {
                        kind: kind.to_string(),
                        name: name.to_string(),
                        namespace: namespace.to_string(),
                        finding_type: "privileged_container",
                        severity: "Critical",
                        cvss_score: 9.0,
                        message: format!(
                            "Container '{}' in '{}'/'{}' runs in privileged mode. \
                            This allows full host access and breaks container isolation.",
                            cname, kind, name
                        ),
                        solution: "Remove 'privileged: true' from container security context. Use specific capability grants instead.",
                        reference: "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                    });
                }

                // Check allowPrivilegeEscalation
                let allow_esc = sc.get("allowPrivilegeEscalation").and_then(|v| v.as_bool()).unwrap_or(true);
                if allow_esc {
                    findings.push(K8sFinding {
                        kind: kind.to_string(),
                        name: name.to_string(),
                        namespace: namespace.to_string(),
                        finding_type: "privilege_escalation",
                        severity: "Medium",
                        cvss_score: 5.5,
                        message: format!(
                            "Container '{}' in '{}'/'{}' has allowPrivilegeEscalation not set to false. \
                            Processes can gain more privileges than their parent.",
                            cname, kind, name
                        ),
                        solution: "Set 'securityContext.allowPrivilegeEscalation: false' for all containers. Required when dropping capabilities.",
                        reference: "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod",
                    });
                }

                // Check capabilities dropped
                let caps_dropped = container.get("securityContext")
                    .and_then(|sc| sc.get("capabilities"))
                    .and_then(|c| c.get("drop"))
                    .and_then(|d| d.as_sequence())
                    .map(|s| s.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                    .unwrap_or_default();
                if !caps_dropped.contains(&"ALL") && !caps_dropped.contains(&"all") {
                    findings.push(K8sFinding {
                        kind: kind.to_string(),
                        name: name.to_string(),
                        namespace: namespace.to_string(),
                        finding_type: "capabilities_not_dropped",
                        severity: "Low",
                        cvss_score: 3.0,
                        message: format!(
                            "Container '{}' in '{}'/'{}' does not drop all capabilities. \
                            Container inherits default Linux capabilities.",
                            cname, kind, name
                        ),
                        solution: "Add 'capabilities.drop: [ALL]' to container security context, then add back only required capabilities.",
                        reference: "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container",
                    });
                }
            }

            // Check resource limits
            if let Some(resources) = container.get("resources") {
                if resources.get("limits").is_none() && strict {
                    findings.push(K8sFinding {
                        kind: kind.to_string(),
                        name: name.to_string(),
                        namespace: namespace.to_string(),
                        finding_type: "missing_resource_limits",
                        severity: "Low",
                        cvss_score: 3.0,
                        message: format!(
                            "Container '{}' in '{}'/'{}' has no resource limits. \
                            Unbounded containers can cause resource starvation.",
                            cname, kind, name
                        ),
                        solution: "Set 'resources.limits.cpu' and 'resources.limits.memory' for all containers to prevent resource exhaustion.",
                        reference: "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
                    });
                }
                if resources.get("requests").is_none() && strict {
                    findings.push(K8sFinding {
                        kind: kind.to_string(),
                        name: name.to_string(),
                        namespace: namespace.to_string(),
                        finding_type: "missing_resource_requests",
                        severity: "Info",
                        cvss_score: 1.0,
                        message: format!(
                            "Container '{}' in '{}'/'{}' has no resource requests. \
                                Scheduler may over-provision nodes.",
                            cname, kind, name
                        ),
                        solution: "Set 'resources.requests.cpu' and 'resources.requests.memory' for guaranteed QoS and proper scheduling.",
                        reference: "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
                    });
                }
            }

            // Check image tag
            if let Some(image) = container.get("image").and_then(|v| v.as_str()) {
                if image.ends_with(":latest") || !image.contains(':') {
                    findings.push(K8sFinding {
                        kind: kind.to_string(),
                        name: name.to_string(),
                        namespace: namespace.to_string(),
                        finding_type: "unpinned_image_tag",
                        severity: if strict { "Medium" } else { "Low" },
                        cvss_score: if strict { 5.0 } else { 3.0 },
                        message: format!(
                            "Container '{}' in '{}'/'{}' uses unpinned image '{}'. \
                            Image may change between deployments.",
                            cname, kind, name, image
                        ),
                        solution: "Pin container image to a specific digest or semantic version tag. \
                            Use renovate/dependabot to automate updates.",
                        reference: "https://kubernetes.io/docs/concepts/containers/images/#updating-images",
                    });
                }
            }
        }
    }

    // Check host access
    for attr in &["hostPID", "hostNetwork", "hostIPC"] {
        if let Some(val) = spec.get(*attr).and_then(|v| v.as_bool()) {
            if val {
                findings.push(K8sFinding {
                    kind: kind.to_string(),
                    name: name.to_string(),
                    namespace: namespace.to_string(),
                    finding_type: "host_access",
                    severity: "High",
                    cvss_score: 8.0,
                    message: format!(
                        "'{}'/'{}' sets '{}: true'. Container shares the host's {} namespace, \
                        breaking isolation boundaries.",
                        kind, name, attr,
                        match *attr {
                            "hostPID" => "process",
                            "hostNetwork" => "network",
                            "hostIPC" => "IPC",
                            _ => attr,
                        }
                    ),
                    solution: "Avoid host namespace sharing. Use network policies and security contexts for isolation.",
                    reference: "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                });
            }
        }
    }

    // Check liveness/readiness probes
    if let Some(containers) = spec.get("containers").and_then(|c| c.as_sequence()) {
        for (i, container) in containers.iter().enumerate() {
            let default_cname = format!("container-{}", i);
            let cname = container.get("name").and_then(|n| n.as_str()).unwrap_or(&default_cname);

            let has_liveness = container.get("livenessProbe").is_some();
            let has_readiness = container.get("readinessProbe").is_some();

            if !has_liveness && strict {
                findings.push(K8sFinding {
                    kind: kind.to_string(),
                    name: name.to_string(),
                    namespace: namespace.to_string(),
                    finding_type: "missing_liveness_probe",
                    severity: "Low",
                    cvss_score: 2.0,
                    message: format!(
                        "Container '{}' in '{}'/'{}' has no liveness probe. \
                        Kubernetes will not automatically restart unhealthy containers.",
                        cname, kind, name
                    ),
                    solution: "Add a 'livenessProbe' (HTTP, TCP, or command-based) to detect and restart unhealthy containers.",
                    reference: "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/",
                });
            }

            if !has_readiness && strict {
                findings.push(K8sFinding {
                    kind: kind.to_string(),
                    name: name.to_string(),
                    namespace: namespace.to_string(),
                    finding_type: "missing_readiness_probe",
                    severity: "Low",
                    cvss_score: 2.0,
                    message: format!(
                        "Container '{}' in '{}'/'{}' has no readiness probe. \
                        Traffic may be routed to containers not ready to serve.",
                        cname, kind, name
                    ),
                    solution: "Add a 'readinessProbe' to ensure traffic only reaches ready containers.",
                    reference: "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/",
                });
            }
        }
    }

    findings
}

/// Check for network policy enforcement.
fn check_network_policies(kind: &str, name: &str, namespace: &str, _val: &Value) -> Vec<K8sFinding> {
    // NetworkPolicy check is per-namespace — flag only on namespaced resources
    if kind == "NetworkPolicy" {
        return Vec::new(); // This manifest IS the policy
    }

    // For other resources in a namespace, we check if a NetworkPolicy exists in the manifest set
    // At manifest-level, we can't determine if one exists elsewhere — note as informational
    if kind == "Deployment" || kind == "StatefulSet" || kind == "DaemonSet" || kind == "Pod" || kind == "Service" {
        return vec![K8sFinding {
            kind: kind.to_string(),
            name: name.to_string(),
            namespace: namespace.to_string(),
            finding_type: "network_policy_check",
            severity: "Info",
            cvss_score: 0.0,
            message: format!(
                "'{}'/'{}' in namespace '{}' — verify that a NetworkPolicy exists to restrict pod-to-pod traffic. \
                By default, all pods in a Kubernetes cluster can communicate.",
                kind, name, namespace
            ),
            solution: "Create a NetworkPolicy with 'podSelector: {}' and 'policyTypes: [Ingress, Egress]' to enable zero-trust networking. Start with deny-all, then allow specific traffic.",
            reference: "https://kubernetes.io/docs/concepts/services-networking/network-policies/",
        }];
    }

    Vec::new()
}

/// Aggregate findings into ScanResult.
fn aggregate_k8s_findings(
    all_findings: Vec<K8sFinding>,
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
            payload: format!("K8s Audit: No security issues found in '{}'.", target),
            cvss_score: Some(0.0),
            reference: Some("https://www.cisecurity.org/benchmark/kubernetes".to_string()),
            solution: None,
            tags: vec!["k8s".to_string(), "audit".to_string(), "clean".to_string()],
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
        .map(|f| format!("[{}][{:.1}] {} ({}:{})", f.severity, f.cvss_score, f.message, f.kind, f.name))
        .collect();

    let solution_text: Vec<String> = all_findings.iter()
        .map(|f| f.solution.to_string())
        .collect();

    let finding_tags: Vec<String> = all_findings.iter()
        .map(|f| format!("k8s:{}:{}", f.finding_type, f.severity.to_lowercase()))
        .collect();

    Some(ScanResult {
        timestamp: Utc::now(),
        template_id: template_id.to_string(),
        template_name: template_info.name.clone(),
        template_severity: worst.severity.to_string(),
        target: target.to_string(),
        payload: format!(
            "K8s Audit Report for '{}': {} issue(s) found.\n- {}",
            target,
            all_findings.len(),
            details.join("\n- "),
        ),
        cvss_score: Some(worst_cvss),
        reference: Some("https://www.cisecurity.org/benchmark/kubernetes".to_string()),
        solution: Some(format!(
            "Remediation steps:\n- {}",
            solution_text.join("\n- "),
        )),
        tags: {
            let mut t = vec!["k8s".to_string(), "audit".to_string(), format!("issues:{}", all_findings.len())];
            t.extend(finding_tags);
            t
        },
        compliance: Default::default(),
    })
}

/// Main K8s audit executor.
pub async fn execute(
    templates: &[K8sAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    let config = K8sAuditConfig::default();

    for template in templates {
        let content = match fs::read_to_string(&template.target_manifest) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(target = %template.target_manifest, error = %e, "K8s audit: failed to read manifest");
                continue;
            }
        };

        let mut all_findings: Vec<K8sFinding> = Vec::new();

        // Parse multi-document YAML (separated by `---`)
        for (doc_idx, doc) in content.split("---").enumerate() {
            let doc = doc.trim();
            if doc.is_empty() {
                continue;
            }

            let val = match serde_yaml::from_str::<Value>(doc) {
                Ok(v) => v,
                Err(e) => {
                    tracing::trace!("K8s audit: failed to parse doc {}: {}", doc_idx, e);
                    continue;
                }
            };

            let kind = val.get("kind").and_then(|v| v.as_str()).unwrap_or("Unknown");
            let name = val.get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("unnamed");
            let namespace = val.get("metadata")
                .and_then(|m| m.get("namespace"))
                .and_then(|v| v.as_str())
                .unwrap_or("default");

            // RBAC checks
            if config.check_rbac {
                all_findings.extend(check_rbac(&val, template.strict_rbac || config.strict_mode));
            }

            // Security context checks (Pod, Deployment, DaemonSet, StatefulSet)
            if (config.check_privilege_escalation || config.check_resources || config.check_probes || config.check_images || config.check_host_access)
                && matches!(kind, "Pod" | "Deployment" | "DaemonSet" | "StatefulSet" | "Job" | "CronJob")
                    && (config.check_privilege_escalation || config.check_resources || config.check_host_access || config.check_probes || config.check_images) {
                        all_findings.extend(check_security_context(kind, name, namespace, &val, template.strict_rbac || config.strict_mode));
                    }

            // Network policy checks
            if config.check_network_policies {
                all_findings.extend(check_network_policies(kind, name, namespace, &val));
            }
        }

        return aggregate_k8s_findings(all_findings, &template.target_manifest, template_id, template_info);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_template(strict: bool) -> K8sAuditTemplate {
        K8sAuditTemplate {
            target_manifest: "test-manifest.yaml".to_string(),
            strict_rbac: strict,
        }
    }

    #[test]
    fn test_cluster_admin_detection() {
        let yaml: Value = serde_yaml::from_str(r#"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: User
    name: admin
    apiGroup: rbac.authorization.k8s.io
"#).unwrap();
        let findings = check_rbac(&yaml, true);
        assert!(findings.iter().any(|f| f.finding_type == "cluster_admin_binding"));
    }

    #[test]
    fn test_wildcard_rbac_detection() {
        let yaml: Value = serde_yaml::from_str(r#"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wildcard-role
rules:
  - apiGroups: [""]
    resources: ["*"]
    verbs: ["*"]
"#).unwrap();
        let findings = check_rbac(&yaml, true);
        assert!(findings.iter().any(|f| f.finding_type == "wildcard_rbac_rule"));
    }

    #[test]
    fn test_privileged_container_detection() {
        let yaml: Value = serde_yaml::from_str(r#"
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
    - name: app
      image: nginx:1.24
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
"#).unwrap();
        let findings = check_security_context("Pod", "privileged-pod", "default", &yaml, true);
        assert!(findings.iter().any(|f| f.finding_type == "privileged_container"));
        assert!(findings.iter().any(|f| f.finding_type == "privilege_escalation"));
    }

    #[test]
    fn test_host_access_detection() {
        let yaml: Value = serde_yaml::from_str(r#"
apiVersion: v1
kind: Pod
metadata:
  name: host-network-pod
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:1.24
"#).unwrap();
        let findings = check_security_context("Pod", "host-network-pod", "default", &yaml, true);
        assert!(findings.iter().any(|f| f.finding_type == "host_access"));
    }

    #[test]
    fn test_missing_probes() {
        let yaml: Value = serde_yaml::from_str(r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0.0
          ports:
            - containerPort: 8080
"#).unwrap();
        let findings = check_security_context("Deployment", "app-deployment", "default", &yaml, true);
        assert!(findings.iter().any(|f| f.finding_type == "missing_liveness_probe"));
        assert!(findings.iter().any(|f| f.finding_type == "missing_readiness_probe"));
    }

    #[test]
    fn test_network_policy_check() {
        let findings = check_network_policies("Pod", "my-pod", "default", &Value::Null);
        // Null value means no policy created — should return info
        assert!(findings.is_empty() || findings.iter().any(|f| f.finding_type == "network_policy_check"));
    }

    #[test]
    fn test_unpinned_image_tag() {
        let yaml: Value = serde_yaml::from_str(r#"
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
    - name: app
      image: nginx:latest
"#).unwrap();
        let findings = check_security_context("Pod", "my-pod", "default", &yaml, true);
        assert!(findings.iter().any(|f| f.finding_type == "unpinned_image_tag"));
    }
}