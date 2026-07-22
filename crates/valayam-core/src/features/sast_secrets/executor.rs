use crate::core::result::ScanResult;
use valayam_models::templates::schema::TemplateInfo;
use chrono::Utc;
use std::fs;
use std::path::Path;
use regex::Regex;
use valayam_models::templates::sast_secrets::SastSecretsTemplate;

pub async fn execute(
    templates: &[SastSecretsTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let dir_path = Path::new(&template.target_dir);
        if !dir_path.exists() || !dir_path.is_dir() {
            continue;
        }

        // Secrets patterns (e.g. AWS keys, generic secrets)
        let pattern = Regex::new(r#"(?i)(api_key|apikey|secret|password|passwd|pwd|aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['"][a-zA-Z0-9/+=]{10,}['"]"#).unwrap();
        
        let mut findings = Vec::new();

        let mut dirs = vec![dir_path.to_path_buf()];
        while let Some(current_dir) = dirs.pop() {
            if let Ok(entries) = fs::read_dir(current_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        dirs.push(path);
                    } else if let Ok(content) = fs::read_to_string(&path) {
                        for (i, line) in content.lines().enumerate() {
                            if pattern.is_match(line) {
                                findings.push(format!("{}:{} -> {}", path.display(), i + 1, line.trim()));
                            }
                        }
                    }
                }
            }
        }

        if !findings.is_empty() {
            return Some(ScanResult { schema_version: "1.0.0".to_string(),
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: "Critical".to_string(),
                target: template.target_dir.clone(),
                payload: format!("SAST Secrets: Found {} hardcoded secrets in source files.", findings.len()),
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
