use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::ImplantDeployTemplate;

pub async fn execute(
    _templates: &[ImplantDeployTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    // TODO: Stub for validation analysis only.
    None
}
