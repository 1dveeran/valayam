use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::RemediationGenTemplate;

pub async fn execute(
    _templates: &[RemediationGenTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    // MVP: Map findings to actionable markdown patch steps
    None
}
