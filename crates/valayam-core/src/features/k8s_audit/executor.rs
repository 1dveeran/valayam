use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use chrono::Utc;
use std::fs;
use serde_yaml::Value;
use super::parser::K8sAuditTemplate;

pub async fn execute(
    templates: &[K8sAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        if let Ok(content) = fs::read_to_string(&template.target_manifest) {
            // Kubernetes manifests can have multiple documents separated by `---`
            for doc in content.split("---") {
                if doc.trim().is_empty() { continue; }
                if let Ok(val) = serde_yaml::from_str::<Value>(doc) {
                    let kind = val.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                    if kind == "ClusterRoleBinding" || kind == "RoleBinding" {
                        if let Some(role_ref) = val.get("roleRef") {
                            let role_name = role_ref.get("name").and_then(|v| v.as_str()).unwrap_or("");
                            if role_name == "cluster-admin" && template.strict_rbac {
                                return Some(ScanResult {
                                    timestamp: Utc::now(),
                                    template_id: template_id.to_string(),
                                    template_name: template_info.name.clone(),
                                    template_severity: "High".to_string(),
                                    target: template.target_manifest.clone(),
                                    payload: "Overly permissive Kubernetes RBAC role: 'cluster-admin' assigned in manifest.".to_string(),
                                    cvss_score: None,
                                    reference: None,
                                    solution: None,
                                    tags: Vec::new(),
                                    compliance: Default::default(),
                                });
                            }
                        }
                    }
                    
                    if kind == "Pod" || kind == "Deployment" {
                        // Check for privileged container
                        // For MVP, just do a string search to avoid deep JSON digging
                        if doc.contains("privileged: true") {
                            return Some(ScanResult {
                                    timestamp: Utc::now(),
                                    template_id: template_id.to_string(),
                                    template_name: template_info.name.clone(),
                                    template_severity: "High".to_string(),
                                    target: template.target_manifest.clone(),
                                    payload: "Privileged container detected in Kubernetes manifest.".to_string(),
                                    cvss_score: None,
                                    reference: None,
                                    solution: None,
                                    tags: Vec::new(),
                                    compliance: Default::default(),
                                });
                        }
                    }
                }
            }
        }
    }
    None
}
