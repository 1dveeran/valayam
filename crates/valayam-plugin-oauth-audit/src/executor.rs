use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;
use valayam_network::network::http::StealthHttpClient;
use valayam_models::templates::oauth_audit::OauthAuditTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[OauthAuditTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
            let req_client = client.client();
            // Try to access the OAuth token/authorize endpoint
            if let Ok(resp) = req_client.get(reqwest_url.clone()).send().await {
                let status = resp.status();
                if let Ok(body) = resp.text().await {
                    let mut is_match = false;
                    if body.contains("redirect_uri=") || status.is_server_error() {
                        is_match = true;
                    }

                    let mut has_implicit_flow = false;
                    
                    // Test for Implicit Flow (response_type=token)
                    let implicit_url = format!("{}/authorize?response_type=token&client_id=test&redirect_uri=https://example.com", target_url.trim_end_matches('/'));
                    if let Ok(imp_resp) = client.send_request("GET", &implicit_url, None, None).await {
                        let imp_status = imp_resp.status().as_u16();
                        // If the server doesn't immediately reject the implicit flow request (e.g. 400 Bad Request)
                        // and instead returns a login page (200) or redirects to login (302), it's likely supported.
                        if imp_status == 200 || imp_status == 302 {
                            let imp_body = imp_resp.text().await.unwrap_or_default();
                            if imp_body.to_lowercase().contains("login") || imp_body.contains("Sign In") || imp_status == 302 {
                                has_implicit_flow = true;
                            }
                        }
                    }

                    if is_match || has_implicit_flow {
                        let mut payload_msg = format!("OAuth misconfiguration or insecure JWT mutation accepted for flow: {}", template.flow_type);
                        if has_implicit_flow {
                            payload_msg = "OAuth provider supports the deprecated and insecure Implicit Flow (response_type=token), which risks leaking access tokens in the browser history or referrer headers.".to_string();
                        }

                        let severity = if has_implicit_flow {
                            "High".to_string()
                        } else {
                            "Medium".to_string()
                        };
                        let mut finding = FindingOwned::from_template_and_info(
                            template_id,
                            template_meta,
                            host.clone(),
                            payload_msg,
                        );
                        finding.severity = severity;
                        return Some(finding);
                    }
                }
            }
        }
    }
    None
}
