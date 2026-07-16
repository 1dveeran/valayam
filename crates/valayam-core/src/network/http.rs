// TODO: Enhance StealthHttpClient for WAF Evasion.
// - Integrate JA3/JA4 TLS spoofing at the `reqwest`/`rustls` layer.
// - Add logic to detect and transparently follow meta-refreshes.
use crate::core::error::ScannerError;
use crate::stealth::tls::{Ja3Ja4Spoofer, Ja3Ja4Profile};
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;
use std::sync::Arc;
use tracing::{debug, warn};

/// Enhanced HTTP client with WAF evasion capabilities.
#[derive(Clone)]
pub struct StealthHttpClient {
    /// Base reqwest client
    client: Client,
    /// Proxy rotator for IP rotation
    proxy_rotator: Option<Arc<crate::stealth::proxy::ProxyRotator>>,
    /// User-Agent rotator for browser impersonation
    user_agent_rotator: Option<Arc<crate::stealth::user_agent::UserAgentRotator>>,
    /// JA3/JA4 spoofer for TLS fingerprint evasion
    #[allow(dead_code)]
    ja3_ja4_spoofer: Option<Ja3Ja4Spoofer>,
    /// Whether to follow meta-refresh redirects
    follow_meta_refresh: bool,
}

impl StealthHttpClient {
    /// Create a new StealthHttpClient with optional stealth features.
    pub fn new(
        use_proxy_rotation: bool,
        use_user_agent_rotation: bool,
        ja3_ja4_profile: Option<Ja3Ja4Profile>,
        follow_meta_refresh: bool,
    ) -> Result<Self, ScannerError> {
        // Build base client
        let client_builder = Client::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .timeout(Duration::from_secs(30));

        // Add proxy rotation if enabled
        let proxy_rotator = if use_proxy_rotation {
            Some(Arc::new(crate::stealth::proxy::ProxyRotator::new()))
        } else {
            None
        };

        // Add user-agent rotation if enabled
        let user_agent_rotator = if use_user_agent_rotation {
            Some(Arc::new(crate::stealth::user_agent::UserAgentRotator::new()?))
        } else {
            None
        };

        // Add JA3/JA4 spoofing if profile specified
        let ja3_ja4_spoofer = ja3_ja4_profile.map(|profile| Ja3Ja4Spoofer::new(profile));

        let client = client_builder.build()?;

        Ok(Self {
            client,
            proxy_rotator,
            user_agent_rotator,
            ja3_ja4_spoofer,
            follow_meta_refresh,
        })
    }

    /// Send an HTTP request with stealth enhancements.
    pub async fn send_request(
        &self,
        method: &str,
        url: &str,
        headers: Option<&HashMap<String, String>>,
        body: Option<&str>,
    ) -> Result<reqwest::Response, ScannerError> {
        // Build the request
        let mut request_builder = self.client.request(
            method.parse::<reqwest::Method>().map_err(|_| ScannerError::InvalidHttpMethod(method.to_string()))?,
            url,
        );

        // Apply headers if provided
        if let Some(headers) = headers {
            for (key, value) in headers {
                request_builder = request_builder.header(key, value);
            }
        }

        // Apply body if provided
        if let Some(body) = body {
            request_builder = request_builder.body(body.to_string());
        }

        // Apply proxy rotation if configured
        // Note: reqwest 0.12+ does not support per-request proxy on RequestBuilder.
        // Proxy should be configured on the ClientBuilder at client creation time.
        // For true per-request rotation, create multiple clients with different proxies.
        if let Some(ref _rotator) = self.proxy_rotator {
            // Proxy rotation is configured but not applied per-request.
            // TODO: Implement proxy rotation by cycling through pre-built clients
        }

        // Apply user-agent rotation if configured
        let request_builder = if let Some(ref rotator) = self.user_agent_rotator {
            // Get next user agent from rotation
            let user_agent = rotator.get_next_user_agent();
            request_builder.header(reqwest::header::USER_AGENT, user_agent)
        } else {
            request_builder
        };

        // Send the request
        let response = request_builder.send().await?;

        // Handle meta-refresh redirects if enabled (non-recursive, follows one level)
        if self.follow_meta_refresh {
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();

            if content_type.contains("text/html") {
                let body = response.text().await?;
                if let Some(redirect_url) = Self::extract_meta_refresh(&body) {
                    debug!("Following meta-refresh redirect to: {}", redirect_url);
                    // Build and send a fresh GET request directly (no further meta-refresh check)
                    let redirect_builder = self
                        .client
                        .request(reqwest::Method::GET, &redirect_url);
                    return redirect_builder.send().await.map_err(ScannerError::from);
                }
            }

            // Could not preserve the original body after checking for meta-refresh
            warn!("Could not preserve original response body after meta-refresh check");
            return Err(ScannerError::ParseError(
                "Body consumed during meta-refresh check".to_string(),
            ));
        }

        Ok(response)
    }

    // TODO: Fix regex quote handling
    /// Extract redirect URL from meta-refresh tag in HTML.
    fn extract_meta_refresh(html: &str) -> Option<String> {
        // Simple regex pattern to find meta-refresh tags
        // <meta http-equiv="refresh" content="5;url=http://example.com/">
        let re = regex::Regex::new(r#"<meta\s+[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["'](\d+)\s*;\s*url\s*=\s*["']([^"']*)["'][^>]*>"#).ok()?;

        // Case-insensitive search
        let re = regex::Regex::new(&format!("(?i){}", re.as_str())).ok()?;

        if let Some(cap) = re.captures(html) {
            // Return the URL part (group 2)
            Some(cap.get(2)?.as_str().to_string())
        } else {
            None
        }
    }

    /// Get the underlying reqwest client for advanced usage.
    pub fn client(&self) -> &Client {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_stealth_http_client_creation() {
        let client = StealthHttpClient::new(true, true, Some(crate::stealth::tls::Ja3Ja4Profile::Chrome), true)
            .expect("Should create client");
        assert!(client.client().timeout() > std::time::Duration::from_secs(0));
    }

    #[tokio::test]
    async fn test_extract_meta_refresh() {
        let html = r#"<html><head><meta http-equiv="refresh" content="5;url=https://example.com/"></head><body></body></html>"#;
        let result = StealthHttpClient::extract_meta_refresh(html);
        assert_eq!(result, Some("https://example.com/".to_string()));

        let html_no_meta = r#"<html><head><title>No redirect</title></head><body></body></html>"#;
        let result = StealthHttpClient::extract_meta_refresh(html_no_meta);
        assert_eq!(result, None);
    }
}