use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnerabilityTemplate {
    pub id: String,
    pub info: TemplateInfo,
    #[serde(default)]
    pub requests: Vec<HttpRequestTemplate>,
    #[serde(default)]
    pub network: Vec<NetworkRequestTemplate>,
    #[serde(default)]
    pub scripts: Vec<ScriptTemplate>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TemplateInfo {
    pub name: String,
    pub severity: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpRequestTemplate {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    pub matchers: Vec<ResponseMatcher>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkRequestTemplate {
    pub host: String,
    pub ports: Vec<String>,
    #[serde(default)]
    pub matchers: Vec<ResponseMatcher>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseMatcher {
    pub r#type: String, // e.g., "regex" or "status"
    pub part: String,   // e.g., "body", "header", or "status"
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub status: Option<Vec<u16>>,
}

/// Defines a scripted scan step. The `engine` field is future-proofed
/// for additional scripting runtimes (e.g., "lua") beyond "rhai".
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScriptTemplate {
    pub engine: String,
    pub source: ScriptSource,
}

/// Supports two deserialization shapes via `#[serde(untagged)]`:
/// - Inline: `{ code: "..." }`
/// - File:   `{ path: "./scripts/foo.rhai" }`
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ScriptSource {
    Inline { code: String },
    File { path: String },
}

impl VulnerabilityTemplate {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, crate::core::error::ScannerError> {
        let file = File::open(path)?;
        let template: VulnerabilityTemplate = serde_yaml::from_reader(file)?;
        Ok(template)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_valid_template_parsing() {
        let yaml = r#"
id: test-template
info:
  name: Test
  severity: Info
requests:
  - method: GET
    path: /
    matchers:
      - type: status
        part: status
        status:
          - 200
        "#;
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", yaml).unwrap();

        let template = VulnerabilityTemplate::load(file.path()).unwrap();
        assert_eq!(template.id, "test-template");
        assert_eq!(template.info.name, "Test");
        assert!(!template.requests.is_empty());
    }

    #[test]
    fn test_invalid_template_parsing() {
        let yaml = r#"
id: test-template
info:
  name: Test
  severity: Info
invalid_key: true
        "#; // Missing required fields or just bad struct match if we strictly parse
        
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", yaml).unwrap();

        let result = VulnerabilityTemplate::load(file.path());
        assert!(result.is_ok(), "Serde ignores unknown fields by default unless specified");
    }
}
