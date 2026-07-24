use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use regex::Regex;
use valayam_models::templates::sast_secrets::SastSecretsTemplate;

pub async fn execute(
    templates: &[SastSecretsTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
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
            let mut metadata = HashMap::new();
            metadata.insert("template_id".to_string(), template_id.to_string());
            metadata.insert("template_name".to_string(), template_meta.template_name().to_string());
            metadata.insert("template_severity".to_string(), "Critical".to_string());
            return Some(FindingOwned::from_template(
                template.target_dir.clone(),
                format!("SAST Secrets: Found {} hardcoded secrets in source files.", findings.len()),
                metadata,
            ));
        }
    }
    None
}
