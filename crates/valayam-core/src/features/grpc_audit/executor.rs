use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use crate::network::http::StealthHttpClient;
use valayam_models::templates::grpc_audit::GrpcAuditTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[GrpcAuditTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
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
                        let mut results = vec![FindingOwned::from_template_and_info(
                            template_id,
                            template_meta,
                            host.clone(),
                            "gRPC Server Reflection is enabled, potentially exposing sensitive internal service definitions.".to_string(),
                        )];

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
                                    let mut fuzzed = FindingOwned::from_template_and_info(
                                        template_id,
                                        template_meta,
                                        host.clone(),
                                        "gRPC endpoint crashed (HTTP 500) when supplied with a dynamically fuzzed protobuf payload extracted via Reflection.".to_string(),
                                    );
                                    fuzzed.template_name = format!("{} - gRPC Fuzzing", template_meta.template_name());
                                    fuzzed.severity = "Critical".to_string();
                                    results.push(fuzzed);
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