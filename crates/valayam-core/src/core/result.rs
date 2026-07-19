// TODO: Expand ScanResult for Compliance & Reporting.
// - Add `compliance` mapping fields (e.g. OWASP, MITRE ATT&CK).
// - Support multiple output formats natively (JSON, SARIF).
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a single, validated vulnerability finding.
/// This structure is serialized to JSON for structured logging and can be
/// converted to other formats like SARIF for integration with security tools.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanResult {
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
    pub template_id: String,
    pub template_name: String,
    pub template_severity: String,
    pub target: String,
    pub payload: String,
    /// Additional compliance information (e.g., OWASP, CWE, NIST, MITRE ATT&CK)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub compliance: HashMap<String, String>,
    /// CVSS score for severity standardization (0.0-10.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f32>,
    /// Solution/remediation guidance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solution: Option<String>,
    /// References for further information ( advisories, blogs, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Tags for categorization and filtering
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl ScanResult {
    /// Convert the scan result to SARIF format for integration with security tools
    #[cfg(feature = "sarif")]
    pub fn to_sarif(&self) -> Result<String, Box<dyn std::error::Error>> {
        // This would require the sarif crate feature
        // For now, we'll return a placeholder that indicates SARIF support
        Ok(format!(
            "{{\"version\":\"2.1.0\",\"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"Valayam\"}}}},{\"results\":[{{\"ruleId\":\"{}\",\"message\":{{\"message\":\"{}\"}},\"level\":\"{}\",\"locations\":[{{\"physicalRegion\":{{\"artifactLocation\":{{\"uri\":\"{}\"}}}}}}]}]}}}}",
            self.template_id,
            self.payload.replace('\"', "\\\""),
            self.map_severity_to_sarif_level(),
            self.target
        ))
    }

    /// Map internal severity to SARIF levels
    #[cfg(feature = "sarif")]
    fn map_severity_to_sarif_level(&self) -> &'static str {
        match self.template_severity.to_ascii_lowercase().as_str() {
            "critical" | "high" => "error",
            "medium" => "warning",
            "low" | "info" => "note",
            _ => "note",
        }
    }

    /// Add a compliance mapping
    pub fn with_compliance(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.compliance.insert(key.into(), value.into());
        self
    }

    /// Add a tag for categorization
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set CVSS score
    pub fn with_cvss_score(mut self, score: f32) -> Self {
        self.cvss_score = Some(score);
        self
    }

    /// Set solution/remediation
    pub fn with_solution(mut self, solution: impl Into<String>) -> Self {
        self.solution = Some(solution.into());
        self
    }

    /// Set reference
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }
}

// Default implementation for easier construction
impl Default for ScanResult {
    fn default() -> Self {
        Self {
            timestamp: Utc::now(),
            template_id: String::new(),
            template_name: String::new(),
            template_severity: String::new(),
            target: String::new(),
            payload: String::new(),
            compliance: HashMap::new(),
            cvss_score: None,
            solution: None,
            reference: None,
            tags: Vec::new(),
        }
    }
}

impl ScanResult {
    pub fn new(
        template_id: &str,
        template_info: &crate::template::schema::TemplateInfo,
        target_url: &str,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            template_id: template_id.to_string(),
            template_name: template_info.name.clone(),
            template_severity: template_info.severity.clone(),
            target: target_url.to_string(),
            payload: String::new(),
            compliance: template_info.compliance.clone(),
            cvss_score: None,
            solution: None,
            reference: None,
            tags: Vec::new(),
        }
    }

    pub fn set_extracted(&mut self, key: &str, value: String) {
        self.payload = format!("{}: {}", key, value);
    }
}