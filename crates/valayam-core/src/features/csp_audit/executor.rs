use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::CspAuditTemplate;

pub async fn execute(
    _templates: &[CspAuditTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    // MVP: Audit Content-Security-Policy header for unsafe directives like unsafe-inline
    None
}
