use valayam_models::result::ScanResult;
use valayam_models::templates::schema::TemplateInfo;
use valayam_models::templates::iot_audit::IotAuditTemplate;
use chrono::Utc;
use std::collections::HashMap;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::time::{timeout, Duration};
use url::Url;

pub async fn execute(
    templates: &[IotAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = if template.target.starts_with("mqtt") || template.target.starts_with("http") {
            if let Ok(parsed) = Url::parse(&template.target) {
                parsed.host_str().unwrap_or(&template.target).to_string()
            } else {
                template.target.clone()
            }
        } else {
            template.target.clone()
        };

        // MQTT default port
        let addr = format!("{}:1883", host);
        let scan_timeout = Duration::from_millis(500);

        if let Ok(Ok(mut stream)) = timeout(scan_timeout, TcpStream::connect(&addr)).await {
            // Send a basic MQTT CONNECT packet
            // Fixed header: Connect Command (0x10) + Remaining Length (0x12)
            // Protocol Name: "MQTT" (0x00, 0x04, 0x4d, 0x51, 0x54, 0x54)
            // Protocol Level: 4 (0x04)
            // Connect Flags: Clean Session (0x02)
            // Keep Alive: 60 (0x00, 0x3c)
            // Client ID Length: 4 (0x00, 0x04)
            // Client ID: "test" (0x74, 0x65, 0x73, 0x74)
            let mqtt_connect_packet: [u8; 18] = [
                0x10, 0x12, 
                0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 
                0x04, 
                0x02, 
                0x00, 0x3c, 
                0x00, 0x04, 0x74, 0x65, 0x73, 0x74
            ];

            if stream.write_all(&mqtt_connect_packet).await.is_ok() {
                // If it accepts the connection and packet without immediate termination, 
                // it might be an open anonymous MQTT broker.
                let mut compliance = HashMap::new();
                compliance.insert("cwe".to_string(), "CWE-284".to_string());
                
                return Some(ScanResult { schema_version: "1.0.0".to_string(),
                    timestamp: Utc::now(),
                    template_id: template_id.to_string(),
                    template_name: template_info.name.clone(),
                    template_severity: "High".to_string(),
                    target: addr,
                    payload: "IoT/MQTT Broker is exposed and accepting connections on port 1883.".to_string(),
                    cvss_score: None,
                    reference: None,
                    solution: None,
                    tags: Vec::new(),
                    compliance,
                });
            }
        }
    }
    None
}
