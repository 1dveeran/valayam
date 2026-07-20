use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileAuditTemplate {
    pub target: Option<String>,
    pub action: String, // "manifest_scan" or "secret_scan"
    pub app_type: String, // "apk" or "ipa"
}
