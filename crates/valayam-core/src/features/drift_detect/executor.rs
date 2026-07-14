use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::DriftDetectTemplate;

pub async fn execute(
    _templates: &[DriftDetectTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    // MVP: Compare current scan context against super::state::load_state
    None
}
