use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::BrowserAuditTemplate;

pub async fn execute(
    _templates: &[BrowserAuditTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    // MVP: Stub. Core delegates Playwright tasks to the Python worker via gRPC/TaskBroker
    None
}
