use crate::core::result::ScanResult;
use crate::template::schema::TemplateInfo;
use crate::network::http::StealthHttpClient;
use chrono::Utc;
use super::parser::GrpcAuditTemplate;

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
                let req_client = client.get_client();
                
                // We send a POST request which is typical for gRPC over HTTP/2. Even if it fails with invalid protobuf, 
                // the server might return HTTP 200 with grpc-status != 12 (UNIMPLEMENTED), indicating the endpoint exists.
                if let Ok(resp) = req_client.post(reqwest_url).send().await {
                    let status = resp.status();
                    let grpc_status = resp.headers().get("grpc-status").and_then(|v| v.to_str().ok()).unwrap_or("");
                    
                    // If it returns HTTP 200 and grpc-status is NOT 12 (Unimplemented), reflection is likely enabled
                    if status.is_success() && grpc_status != "12" {
                        return Some(ScanResult {
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: "High".to_string(),
                            target: host.clone(),
                            payload: "gRPC Server Reflection is enabled, potentially exposing sensitive internal service definitions.".to_string(),
                            compliance: Default::default(),
                        });
                    }
                }
            }
        }
    }
    None
}
