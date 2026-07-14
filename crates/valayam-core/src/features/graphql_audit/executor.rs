use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::GraphqlAuditTemplate;

pub async fn execute(
    _templates: &[GraphqlAuditTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    // MVP: Send an introspection query
    None
}
