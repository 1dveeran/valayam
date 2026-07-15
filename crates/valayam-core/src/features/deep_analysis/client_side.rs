use crate::core::result::ScanResult;
use crate::network::http::StealthHttpClient;
use super::parser::DeepAnalysisTemplate;

pub async fn analyze(
    client: &StealthHttpClient,
    target_url: &str,
    template: &DeepAnalysisTemplate,
) -> Option<ScanResult> {
    if template.analysis_type == "wasm_decompile" {
        // Fetch WASM file
        if let Ok(res) = client.get_client().get(target_url).send().await {
            if let Ok(bytes) = res.bytes().await {
                let mut found_strings = Vec::new();
                for payload in wasmparser::Parser::new(0).parse_all(&bytes) {
                    if let Ok(wasmparser::Payload::DataSection(data)) = payload {
                        for d in data {
                            if let Ok(entry) = d {
                                if let Ok(s) = std::str::from_utf8(entry.data) {
                                    // Naive check for endpoints or secrets
                                    if s.contains("api/") || s.contains("token=") {
                                        found_strings.push(s.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
                
                if !found_strings.is_empty() {
                    return Some(ScanResult {
                        timestamp: chrono::Utc::now(),
                        template_id: "deep-analysis-wasm".to_string(),
                        template_name: "WASM Hardcoded Secrets".to_string(),
                        template_severity: "HIGH".to_string(),
                        target: target_url.to_string(),
                        payload: format!("Found {} suspicious strings", found_strings.len()),
                        compliance: std::collections::HashMap::new(),
                    });
                }
            }
        }
    } else if template.analysis_type == "source_map" {
        // Fetch .map file
        if let Ok(res) = client.get_client().get(target_url).send().await {
            if let Ok(bytes) = res.bytes().await {
                if let Ok(map) = sourcemap::decode(bytes.as_ref()) {
                    if let sourcemap::DecodedMap::Regular(sm) = map {
                        for src_id in 0..sm.get_source_count() {
                            if let Some(content) = sm.get_source_contents(src_id) {
                                if content.contains("process.env.API_KEY") || content.contains("AWS_ACCESS_KEY_ID") {
                                    return Some(ScanResult {
                                        timestamp: chrono::Utc::now(),
                                        template_id: "deep-analysis-sourcemap".to_string(),
                                        template_name: "Source Map Secrets Exposure".to_string(),
                                        template_severity: "CRITICAL".to_string(),
                                        target: target_url.to_string(),
                                        payload: "Exposed environment variables found in source map".to_string(),
                                        compliance: std::collections::HashMap::new(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    None
}
