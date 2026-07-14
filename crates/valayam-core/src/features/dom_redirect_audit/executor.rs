use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::DomRedirectAuditTemplate;

pub async fn execute(
    _templates: &[DomRedirectAuditTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    // MVP: Trace location.href assignments from URL query parameters
    None
}
