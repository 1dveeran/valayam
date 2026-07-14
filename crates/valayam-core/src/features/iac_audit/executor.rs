use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::IacAuditTemplate;

pub async fn execute(
    _templates: &[IacAuditTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    // MVP: Iterate through files, parse using hcl-rs or yaml depending on the type,
    // and evaluate matchers against the resulting JSON tree.
    None
}
