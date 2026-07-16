use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use chrono::Utc;
use url::Url;
use super::parser::ScadaAuditTemplate;

pub async fn execute(
    target_url: &str,
    templates: &[ScadaAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
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
        let results = crate::network::tcp::scan_ports(&host, &[port.to_string()], None, false).await;

        if let Some(_open_port) = results.first() {
            return Some(ScanResult {
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: "Critical".to_string(),
                target: host.clone(),
                payload: format!("CRITICAL: Exposed {} SCADA interface detected on port {}!", protocol.to_uppercase(), port),
                cvss_score: None,
                reference: None,
                solution: None,
                tags: Vec::new(),
                compliance: Default::default(),
            });
        }
    }
    None
}
