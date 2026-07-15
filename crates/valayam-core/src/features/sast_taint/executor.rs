use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use chrono::Utc;
use std::fs;
use std::path::Path;
use regex::Regex;
use super::parser::SastTaintTemplate;

pub async fn execute(
    templates: &[SastTaintTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let dir_path = Path::new(&template.target_dir);
        if !dir_path.exists() || !dir_path.is_dir() {
            continue;
        }

        // Taint sinks patterns (e.g. SQL injection sinks, exec)
        let pattern = Regex::new(r"(?i)(execute|eval|exec|system|query)\s*\([^)]*\$").unwrap();
        
        let mut findings = Vec::new();

        // Simple recursive directory walk
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
            return Some(ScanResult {
                timestamp: Utc::now(),
                template_id: template_id.to_string(),
                template_name: template_info.name.clone(),
                template_severity: "High".to_string(),
                target: template.target_dir.clone(),
                payload: format!("SAST Taint: Found {} insecure sinks (e.g., potential SQLi/Command Injection) in source files.", findings.len()),
                compliance: Default::default(),
            });
        }
    }
    None
}
