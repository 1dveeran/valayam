use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use chrono::Utc;
use super::parser::ContainerAuditTemplate;

pub async fn execute(
    templates: &[ContainerAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        // MVP to Prod: We check if the target_image uses "latest" tag
        if template.target_image.ends_with(":latest") || !template.target_image.contains(':') {
            return Some(ScanResult {
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: "Low".to_string(),
                target: template.target_image.clone(),
                payload: "Container Audit: Image uses the 'latest' tag or no tag, which can lead to unpredictable deployments and security drift.".to_string(),
                cvss_score: None,
                reference: None,
                solution: None,
                tags: Vec::new(),
                compliance: Default::default(),
            });
        }
    }
    None
}
