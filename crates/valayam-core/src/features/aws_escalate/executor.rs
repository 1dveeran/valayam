use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::AwsEscalateTemplate;

pub async fn execute(
    _templates: &[AwsEscalateTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    // MVP: Forge HTTP requests to STS and IAM to enumerate roles
    None
}
