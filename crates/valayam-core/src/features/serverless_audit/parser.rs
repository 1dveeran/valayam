use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerlessAuditTemplate {
    pub target: Option<String>,
    pub action: String, // "iam_scan" or "trigger_scan"
    pub framework: String, // "serverless" or "aws_sam"
}
