use crate::core::result::ScanResult;
use crate::network::tcp;
use crate::template::schema::TemplateInfo;
use chrono::Utc;
use super::parser::PortScanTemplate;

pub async fn execute(
    target_host: &str,
    templates: &[PortScanTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host_to_scan = template.target.replace("{{Hostname}}", target_host);
        
        // Convert Vec<u16> to Vec<String> for tcp::scan_ports
        let ports_as_strings: Vec<String> = template.ports.iter().map(|p| p.to_string()).collect();

        // We do not need banner grabbing for basic port scan, just checking if open
        let port_results = tcp::scan_ports(&host_to_scan, &ports_as_strings, None).await;

        if let Some(_first_open) = port_results.first() {
            let open_ports: Vec<String> = port_results.iter().map(|r| r.port.to_string()).collect();
            return Some(ScanResult {
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: template_info.severity.clone(),
                target: host_to_scan,
                payload: format!("Unexpected open TCP ports detected: {}", open_ports.join(", ")),
                compliance: Default::default(),
            });
        }
    }
    None
}
