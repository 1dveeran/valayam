use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::SastTaintTemplate;

pub async fn execute(
    _templates: &[SastTaintTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    // MVP: Run fast static analysis over provided source code directories to find direct insecure sinks
    None
}
