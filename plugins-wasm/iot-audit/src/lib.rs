use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner};
use extism_pdk::*;
use std::collections::HashMap;

#[derive(Default)]
pub struct WasmScannerImpl;

impl WasmScanner for WasmScannerImpl {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        extism_pdk::info!("Starting scan for iot_audit");
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let target_url = input.context.get("TARGET_URL").map(|s| s.as_str()).unwrap_or("");
        
        let mut all_findings = Vec::new();
        
        let mut metadata = HashMap::new();
        metadata.insert("template_id".to_string(), template_id.clone());
        
        let w_url = format!("{}?audit=1", target_url);
        extism_pdk::info!("Creating HttpRequest for w_url: {}", w_url);
        let mut req = HttpRequest::new(&w_url);
        req.method = Some("GET".to_string());
        
        extism_pdk::info!("Sending http::request");
        if let Ok(res) = extism_pdk::http::request::<()>(&req, None) {
            if res.status_code() == 200 {
                all_findings.push(Finding {
                    template_id,
                    template_name: format!("{} (Audit Match)", input.template.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown")),
                    severity: "Info".to_string(),
                    target: target_url.to_string(),
                    matched_at: target_url.to_string(),
                    description: Some("Audit completed successfully via Wasm.".to_string()),
                    solution: None,
                    extracted_data: None,
                    metadata,
                });
            }
        }

        extism_pdk::info!("Returning output");
        if all_findings.is_empty() {
            Ok(WasmOutput { matched: false, count: 0, findings: vec![] })
        } else {
            let count = all_findings.len();
            Ok(WasmOutput { matched: true, count, findings: all_findings })
        }
    }
}

export_plugin!(WasmScannerImpl);
