use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::SchemaDriftTemplate;

pub async fn execute(
    _templates: &[SchemaDriftTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    // MVP: Compare active endpoints against OpenAPI spec to find shadow APIs
    None
}
