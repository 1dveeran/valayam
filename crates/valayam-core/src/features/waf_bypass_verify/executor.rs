use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::WafBypassVerifyTemplate;

pub async fn execute(
    _templates: &[WafBypassVerifyTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    // MVP: Send non-destructive payloads (XSS, path traversal) to verify WAF blocking behavior
    None
}
