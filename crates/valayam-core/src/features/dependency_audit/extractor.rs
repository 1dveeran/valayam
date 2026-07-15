use std::fs;
use std::path::Path;
use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

pub struct Dependency {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

pub fn extract_dependencies(lockfile_path: &Path) -> Vec<Dependency> {
    let mut deps = Vec::new();

    if let Some(filename) = lockfile_path.file_name().and_then(|s| s.to_str()) {
        if let Ok(content) = fs::read_to_string(lockfile_path) {
            match filename {
                "Cargo.lock" => {
                    if let Ok(parsed) = content.parse::<TomlValue>() {
                        if let Some(packages) = parsed.get("package").and_then(|v| v.as_array()) {
                            for pkg in packages {
                                if let (Some(name), Some(version)) = (
                                    pkg.get("name").and_then(|v| v.as_str()),
                                    pkg.get("version").and_then(|v| v.as_str()),
                                ) {
                                    deps.push(Dependency {
                                        ecosystem: "cargo".to_string(),
                                        name: name.to_string(),
                                        version: version.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
                "package-lock.json" => {
                    if let Ok(parsed) = serde_json::from_str::<JsonValue>(&content) {
                        if let Some(dependencies) = parsed.get("dependencies").and_then(|v| v.as_object()) {
                            for (name, data) in dependencies {
                                if let Some(version) = data.get("version").and_then(|v| v.as_str()) {
                                    deps.push(Dependency {
                                        ecosystem: "npm".to_string(),
                                        name: name.clone(),
                                        version: version.to_string(),
                                    });
                                }
                            }
                        } else if let Some(packages) = parsed.get("packages").and_then(|v| v.as_object()) {
                            // v2 and v3 package-lock.json formats
                            for (name, data) in packages {
                                if name.is_empty() { continue; } // Root project itself
                                let actual_name = name.strip_prefix("node_modules/").unwrap_or(name);
                                if let Some(version) = data.get("version").and_then(|v| v.as_str()) {
                                    deps.push(Dependency {
                                        ecosystem: "npm".to_string(),
                                        name: actual_name.to_string(),
                                        version: version.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    
    deps
}
