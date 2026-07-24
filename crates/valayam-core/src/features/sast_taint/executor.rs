use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use regex::Regex;
use valayam_models::templates::sast_taint::SastTaintTemplate;

pub async fn execute(
    templates: &[SastTaintTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
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
            let mut metadata = HashMap::new();
            metadata.insert("template_id".to_string(), template_id.to_string());
            metadata.insert("template_name".to_string(), template_meta.template_name().to_string());
            metadata.insert("template_severity".to_string(), "High".to_string());
            return Some(FindingOwned::from_template(
                template.target_dir.clone(),
                format!("SAST Taint: Found {} insecure sinks (e.g., potential SQLi/Command Injection) in source files.", findings.len()),
                metadata,
            ));
        }
    }
    None
}
