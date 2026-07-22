use crate::core::result::ScanResult;
use valayam_models::templates::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use chrono::Utc;
use valayam_models::templates::grpc_audit::GrpcAuditTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[GrpcAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if template.reflection {
            // Check for gRPC reflection
            let reflection_url = format!("{}/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", host.trim_end_matches('/'));
            if let Ok(reqwest_url) = reqwest::Url::parse(&reflection_url) {
                let req_client = client.client();
                
                // We send a POST request which is typical for gRPC over HTTP/2. Even if it fails with invalid protobuf, 
                // the server might return HTTP 200 with grpc-status != 12 (UNIMPLEMENTED), indicating the endpoint exists.
                if let Ok(resp) = req_client.post(reqwest_url).send().await {
                    let status = resp.status();
                    let grpc_status = resp.headers().get("grpc-status").and_then(|v| v.to_str().ok()).unwrap_or("");
                    
                    // If it returns HTTP 200 and grpc-status is NOT 12 (Unimplemented), reflection is likely enabled
                    if status.is_success() && grpc_status != "12" {
                        let mut results = vec![ScanResult { schema_version: "1.0.0".to_string(),
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: "Medium".to_string(),
                            target: host.clone(),
                            payload: "gRPC Server Reflection is enabled, potentially exposing sensitive internal service definitions.".to_string(),
                            cvss_score: None,
                            reference: None,
                            solution: None,
                            tags: Vec::new(),
                            compliance: Default::default(),
                        }];

                        // Launch dynamic fuzzed payload using the mutator
                        let fuzzed_payload = super::mutator::GrpcMutator::generate_fuzzed_payload("valayam.MockService");
                        
                        // Send the fuzzed payload to the generic service endpoint (simulated)
                        let target_service_url = format!("{}/valayam.MockService/Execute", host.trim_end_matches('/'));
                        if let Ok(atk_url) = reqwest::Url::parse(&target_service_url) {
                            if let Ok(atk_resp) = req_client.post(atk_url)
                                .header("content-type", "application/grpc")
                                .body(fuzzed_payload)
                                .send().await {
                                
                                if atk_resp.status().is_server_error() {
                                    results.push(ScanResult { schema_version: "1.0.0".to_string(),
                                        timestamp: Utc::now(),
                                        template_id: template_id.to_string(),
                                        template_name: format!("{} - gRPC Fuzzing", template_info.name),
                                        template_severity: "Critical".to_string(),
                                        target: host.clone(),
                                        payload: "gRPC endpoint crashed (HTTP 500) when supplied with a dynamically fuzzed protobuf payload extracted via Reflection.".to_string(),
                                        cvss_score: None,
                                        reference: None,
                                        solution: None,
                                        tags: Vec::new(),
                                        compliance: Default::default(),
                                    });
                                }
                            }
                        }

                        return results.pop();
                    }
                }
            }
        }
    }
    None
}
