use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use chrono::Utc;
use std::fs;
use std::path::Path;
use super::parser::IacAuditTemplate;

pub async fn execute(
    templates: &[IacAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let path = Path::new(&template.target);
        if !path.exists() { continue; }

        if let Ok(content) = fs::read_to_string(path) {
            match template.r#type.as_str() {
                "terraform" => {
                    // MVP Check for 0.0.0.0/0
                    if content.contains("0.0.0.0/0") {
                        return Some(ScanResult {
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: "High".to_string(),
                            target: template.target.clone(),
                            payload: "Terraform IaC Audit: Overly permissive CIDR block (0.0.0.0/0) detected.".to_string(),
                            compliance: Default::default(),
                        });
                    }
                },
                "docker" => {
                    // Check for running as root
                    if content.contains("USER root") || !content.contains("USER") {
                        return Some(ScanResult {
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: "Medium".to_string(),
                            target: template.target.clone(),
                            payload: "Docker IaC Audit: Container might run as root (no explicit non-root USER defined).".to_string(),
                            compliance: Default::default(),
                        });
                    }
                },
                _ => {}
            }
        }
    }
    None
}
