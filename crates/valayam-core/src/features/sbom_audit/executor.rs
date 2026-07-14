use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::SbomAuditTemplate;

pub async fn execute(
    _templates: &[SbomAuditTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    // MVP: Parse the target file, extract dependencies, and optionally check OSV.dev
    None
}
