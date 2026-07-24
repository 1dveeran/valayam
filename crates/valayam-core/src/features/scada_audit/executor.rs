use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use url::Url;
use valayam_models::templates::scada_audit::ScadaAuditTemplate;

pub async fn execute(
    target_url: &str,
    templates: &[ScadaAuditTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
    for template in templates {
        // Parse host from target_url
        let host = if let Ok(parsed) = Url::parse(target_url) {
            parsed.host_str().unwrap_or(target_url).to_string()
        } else {
            target_url.to_string()
        };
        
        let protocol = template.protocol.to_lowercase();
        let port = match protocol.as_str() {
            "modbus" => 502,
            "dnp3" => 20000,
            "s7" => 102,
            "iec104" => 2404,
            _ => {
                tracing::warn!("Unsupported SCADA protocol: {}", protocol);
                continue;
            }
        };

        // Scan the specific SCADA port using the network TCP port scanner module
        let results = crate::network::tcp::scan_ports(&host, &[port.to_string()], None, false, None).await;

        if let Some(_open_port) = results.first() {
            return Some(FindingOwned::from_template_and_info(
                template_id,
                template_meta,
                &host,
                format!("CRITICAL: Exposed {} SCADA interface detected on port {}!", protocol.to_uppercase(), port),
            ));
        }
    }
    None
}
