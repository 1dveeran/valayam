use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use super::parser::GrpcAuditTemplate;

pub async fn execute(
    _templates: &[GrpcAuditTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    // MVP: Try to use gRPC reflection to fetch services
    None
}
