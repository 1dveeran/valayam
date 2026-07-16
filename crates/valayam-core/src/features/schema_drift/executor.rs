use crate::core::result::ScanResult;
use crate::network::http::StealthHttpClient;
use crate::template::schema::TemplateInfo;
use crate::features::crawler::Crawler;
use chrono::Utc;
use std::sync::Arc;
use super::parser::SchemaDriftTemplate;

pub async fn execute(
    target_host: &str,
    http_client: &StealthHttpClient,
    templates: &[SchemaDriftTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_host);

        // Parse OpenAPI spec to get documented paths
        let documented_paths = match crate::features::crawler::parsers::openapi_generator::generate_template_from_openapi(&template.openapi_spec) {
            Ok(parsed) => {
                let mut paths = std::collections::HashSet::new();
                for req in parsed.requests {
                    // Extract just the path part, discarding query strings for comparison if needed
                    // But openapi paths are usually like /api/v1/users/{{id}}
                    let base_path = req.path.split('?').next().unwrap_or(&req.path).to_string();
                    paths.insert(base_path);
                }
                paths
            }
            Err(e) => {
                tracing::warn!("Failed to parse OpenAPI spec for schema drift: {}", e);
                continue;
            }
        };

        // Initialize Crawler for shallow crawl (depth 1)
        let crawler = Crawler::new(Arc::new(http_client.clone()), &host, 1, None, None);
        
        match crawler {
            Ok(c) => {
                let discovered_urls = c.run().await;
                
                let mut shadow_apis = Vec::new();

                for url in discovered_urls {
                    if let Ok(parsed_url) = reqwest::Url::parse(&url) {
                        let path = parsed_url.path();
                        
                        // Check if path exists in OpenAPI spec
                        // A naive check: does the documented path match the discovered path?
                        // Since documented paths can have variables like {{id}}, we check if any prefix matches or do a regex match.
                        // For MVP, we'll do a simple substring or exact match check.
                        let mut found = false;
                        for doc_path in &documented_paths {
                            let doc_base = doc_path.split("{{").next().unwrap_or(doc_path);
                            if path.starts_with(doc_base) {
                                found = true;
                                break;
                            }
                        }

                        if !found {
                            shadow_apis.push(path.to_string());
                        }
                    }
                }

                if !shadow_apis.is_empty() {
                    return Some(ScanResult {
                        timestamp: Utc::now(),
                        template_id: template_id.to_string(),
                        template_name: template_info.name.clone(),
                        template_severity: "Medium".to_string(),
                        target: host.clone(),
                        payload: format!(
                            "Schema Drift (Shadow API) detected! The following {} endpoints were discovered but are NOT documented in the OpenAPI spec: {:?}",
                            shadow_apis.len(),
                            shadow_apis
                        ),
                        cvss_score: None,
                        reference: None,
                        solution: None,
                        tags: Vec::new(),
                        compliance: Default::default(),
                    });
                }
            }
            Err(e) => {
                tracing::warn!("Failed to initialize crawler for schema drift: {}", e);
            }
        }
    }
    None
}
