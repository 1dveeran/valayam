use valayam_plugin_sdk::{export_plugin, extism_pdk, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::HttpRequest;
use serde_json::Value;

#[derive(Default)]
pub struct HeaderScorecardScanner;

impl WasmScanner for HeaderScorecardScanner {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let mut findings = Vec::new();

        let template_id = input
            .template
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let template_name = input
            .template
            .get("info")
            .and_then(|i| i.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("Header Scorecard")
            .to_string();

        let target = input
            .context
            .get("BaseURL")
            .cloned()
            .unwrap_or_else(|| "http://localhost".to_string());

        // Parse required_headers from the template
        let required_headers = match input.template.get("header_scorecard") {
            Some(Value::Array(arr)) => {
                let mut req_headers = Vec::new();
                for item in arr {
                    if let Some(h) = item.get("required_headers") {
                        if let Some(headers_arr) = h.as_array() {
                            for header in headers_arr {
                                if let Some(h_str) = header.as_str() {
                                    req_headers.push(h_str.to_lowercase());
                                }
                            }
                        }
                    }
                }
                req_headers
            }
            _ => vec![],
        };

        if required_headers.is_empty() {
            return Ok(WasmOutput {
                matched: false,
                count: 0,
                findings: vec![],
            });
        }

        let req = HttpRequest::new(&target).with_method("GET");
        let res = extism_pdk::http::request::<()>(&req, None)?;
        
        let res_headers = res.headers();
        let mut missing = Vec::new();
        
        // Check for missing headers
        for req_header in &required_headers {
            if !res_headers.contains_key(req_header) {
                missing.push(req_header.clone());
            }
        }

        if !missing.is_empty() {
            findings.push(Finding {
                template_id: template_id.clone(),
                template_name: template_name.clone(),
                severity: "Medium".to_string(),
                target: target.clone(),
                matched_at: format!("Missing recommended security headers: {:?}", missing),
                description: Some(format!("The response is missing the following recommended security headers: {:?}", missing)),
                solution: Some("Configure the web server to include the recommended security headers in its responses.".to_string()),
                extracted_data: None,
                metadata: std::collections::HashMap::new(),
            });
        }

        Ok(WasmOutput {
            matched: !findings.is_empty(),
            count: findings.len(),
            findings,
        })
    }
}

export_plugin!(HeaderScorecardScanner);
