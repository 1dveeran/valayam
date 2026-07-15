use crate::core::result::ScanResult;
use crate::network::http::StealthHttpClient;
use super::parser::DeepAnalysisTemplate;
use serde_json::json;

pub async fn mutate_and_test(
    client: &StealthHttpClient,
    target_url: &str,
    template: &DeepAnalysisTemplate,
) -> Option<ScanResult> {
    // Basic MVP: assume a local llama.cpp server is running at http://localhost:8080
    // In a real scenario, this endpoint could be configurable.
    let llm_endpoint = "http://localhost:8080/completion";
    
    let prompt = template.prompt.clone().unwrap_or_else(|| "Mutate this payload to bypass WAF: <script>alert(1)</script>".to_string());
    
    let request_body = json!({
        "prompt": prompt,
        "n_predict": 128
    });
    
    let response = client
        .get_client()
        .post(llm_endpoint)
        .json(&request_body)
        .send()
        .await
        .ok()?;

    if let Ok(json_res) = response.json::<serde_json::Value>().await {
        if let Some(content) = json_res.get("content").and_then(|c| c.as_str()) {
            let mutated_payload = content.trim();
            
            // Fire the mutated payload at the target URL
            let test_req = client
                .get_client()
                .post(target_url)
                .body(mutated_payload.to_string())
                .send()
                .await;
                
            if let Ok(res) = test_req {
                if res.status().is_success() {
                    return Some(ScanResult {
                        timestamp: chrono::Utc::now(),
                        template_id: "deep-analysis-llm".to_string(),
                        template_name: "LLM Mutator WAF Bypass".to_string(),
                        template_severity: "CRITICAL".to_string(),
                        target: target_url.to_string(),
                        payload: mutated_payload.to_string(),
                        compliance: std::collections::HashMap::new(),
                    });
                }
            }
        }
    }
    
    None
}
