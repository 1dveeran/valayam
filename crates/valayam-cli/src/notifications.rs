use reqwest::Client;
use serde_json::json;
use valayam_core::core::result::ScanResult;

/// Sends real-time notifications to webhooks (Slack, Teams, Discord).
pub struct Notifier;

impl Notifier {
    /// Send an alert to a Slack webhook for high-severity findings.
    pub async fn send_slack_alert(webhook_url: &str, result: &ScanResult) -> Result<(), String> {
        let client = Client::new();
        let payload = json!({
            "text": format!("🚨 *Vulnerability Found!*\n*Target:* {}\n*Template:* {}\n*Severity:* {}", 
                            result.target, result.template_name, result.template_severity)
        });
        
        client.post(webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;
            
        Ok(())
    }
}
