// TODO: Enhance StealthHttpClient for WAF Evasion.
// - Integrate JA3/JA4 TLS spoofing at the `reqwest`/`rustls` layer.
// - Add logic to detect and transparently follow meta-refreshes.
// - Implement proxy health-checking before using a proxy from the pool.
use crate::core::error::ScannerError;
use crate::stealth::tls::{Ja3Ja4Spoofer, Ja3Ja4Profile};
use crate::stealth::proxy::ProxyRotator;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tracing::{debug, warn};

/// A pool of reqwest clients, each configured with a different proxy.
/// Clients are created lazily and reused.
struct ProxiedClientPool {
    /// Proxy rotator for cycling through proxies
    rotator: Arc<Mutex<ProxyRotator>>,
    /// Pre-built reqwest clients per proxy address
    clients: Mutex<HashMap<String, Client>>,
    /// Next proxy to use (round-robin)
    current_proxy: Mutex<Option<String>>,
}

impl ProxiedClientPool {
    fn new(rotator: ProxyRotator) -> Self {
        Self {
            rotator: Arc::new(Mutex::new(rotator)),
            clients: Mutex::new(HashMap::new()),
            current_proxy: Mutex::new(None),
        }
    }

    /// Get a reqwest client for the next proxy in rotation.
    fn next_client(&self) -> Option<(Client, String)> {
        let proxy_address = {
            let rotator = self.rotator.lock().ok()?;
            rotator.next().map(|s| s.to_string())
        }?;

        // Check if we already have a client for this proxy
        if let Ok(clients) = self.clients.lock() {
            if let Some(client) = clients.get(&proxy_address) {
                if let Ok(mut current) = self.current_proxy.lock() {
                    *current = Some(proxy_address.clone());
                }
                return Some((client.clone(), proxy_address));
            }
        }

        // Build a new client with this proxy
        let proxy = match reqwest::Proxy::all(&proxy_address) {
            Ok(p) => p,
            Err(e) => {
                warn!(proxy = %proxy_address, error = %e, "Failed to create proxy configuration");
                return None;
            }
        };

        let client = match Client::builder()
            .proxy(proxy)
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .timeout(Duration::from_secs(30))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(proxy = %proxy_address, error = %e, "Failed to build proxied client");
                return None;
            }
        };

        // Cache the client
        if let Ok(mut clients) = self.clients.lock() {
            clients.insert(proxy_address.clone(), client.clone());
        }
        if let Ok(mut current) = self.current_proxy.lock() {
            *current = Some(proxy_address.clone());
        }

        Some((client, proxy_address))
    }

    /// Report a success for the current proxy.
    fn record_success(&self) {
        if let Ok(current) = self.current_proxy.lock() {
            if let Some(ref addr) = *current {
                if let Ok(mut rotator) = self.rotator.lock() {
                    rotator.record_success(addr);
                }
            }
        }
    }

    /// Report a failure for the current proxy.
    fn record_failure(&self) {
        if let Ok(current) = self.current_proxy.lock() {
            if let Some(ref addr) = *current {
                if let Ok(mut rotator) = self.rotator.lock() {
                    rotator.record_failure(addr);
                }
            }
        }
    }
}

/// Enhanced HTTP client with WAF evasion capabilities.
#[derive(Clone)]
pub struct StealthHttpClient {
    /// Base reqwest client (without proxy)
    client: Client,
    /// Pool of proxy-backed clients for IP rotation
    proxy_client_pool: Option<Arc<ProxiedClientPool>>,
    /// Proxy rotator for IP rotation metadata
    #[allow(dead_code)]
    proxy_rotator: Option<Arc<Mutex<ProxyRotator>>>,
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
        let (proxy_client_pool, proxy_rotator) = if use_proxy_rotation {
            let rotator = ProxyRotator::new();
            let pool = ProxiedClientPool::new(rotator.clone());
            (
                Some(Arc::new(pool)),
                Some(Arc::new(Mutex::new(rotator))),
            )
        } else {
            (None, None)
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
            proxy_client_pool,
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
        let http_method: reqwest::Method = method
            .parse()
            .map_err(|_| ScannerError::InvalidHttpMethod(method.to_string()))?;

        // If proxy rotation is configured, use a proxied client from the pool.
        if let Some(ref pool) = self.proxy_client_pool {
            if let Some((proxied_client, proxy_addr)) = pool.next_client() {
                debug!(proxy = %proxy_addr, "Using proxied client for request");
                let mut proxied_req = proxied_client.request(http_method, url);
                // Apply headers
                if let Some(hdrs) = headers {
                    for (key, value) in hdrs {
                        proxied_req = proxied_req.header(key, value);
                    }
                }
                // Apply body
                if let Some(b) = body {
                    proxied_req = proxied_req.body(b.to_string());
                }
                // Apply user-agent rotation
                if let Some(ref rotator) = self.user_agent_rotator {
                    let ua = rotator.get_next_user_agent();
                    proxied_req = proxied_req.header(reqwest::header::USER_AGENT, ua);
                }
                return send_with_proxied_req(proxied_req, pool, self.follow_meta_refresh).await;
            } else {
                warn!("No healthy proxies available, falling back to direct connection");
            }
        }

        // Build the request on the base (direct) client
        let mut request_builder = self.client.request(http_method, url);

        // Apply headers if provided
        if let Some(hdrs) = headers {
            for (key, value) in hdrs {
                request_builder = request_builder.header(key, value);
            }
        }

        // Apply body if provided
        if let Some(b) = body {
            request_builder = request_builder.body(b.to_string());
        }

        // Apply user-agent rotation if configured
        if let Some(ref rotator) = self.user_agent_rotator {
            let user_agent = rotator.get_next_user_agent();
            request_builder = request_builder.header(reqwest::header::USER_AGENT, user_agent);
        }

        // Send the request
        let response = request_builder.send().await?;

        // Handle meta-refresh redirects if enabled
        if self.follow_meta_refresh {
            handle_meta_refresh(response, &self.client).await
        } else {
            Ok(response)
        }
    }

    /// Get the underlying reqwest client for advanced usage.
    pub fn client(&self) -> &Client {
        &self.client
    }
}

/// Send a request via a proxied client with success/failure tracking.
/// Meta-refresh following is not supported in proxy mode (the proxied client's redirect
/// policy handles it instead).
async fn send_with_proxied_req(
    request_builder: reqwest::RequestBuilder,
    pool: &ProxiedClientPool,
    _follow_meta_refresh: bool,
) -> Result<reqwest::Response, ScannerError> {
    match request_builder.send().await {
        Ok(response) => {
            pool.record_success();
            if response.status().is_server_error() {
                pool.record_failure();
            }
            // Meta-refresh following in proxy mode would require the base client,
            // which would bypass the proxy — skip for proxy mode.
            Ok(response)
        }
        Err(e) => {
            pool.record_failure();
            Err(ScannerError::HttpClientError(e))
        }
    }
}

/// Handle meta-refresh redirects by checking the response body.
/// Returns the body text and an optional redirect URL.
async fn handle_meta_refresh(
    response: reqwest::Response,
    client: &Client,
) -> Result<reqwest::Response, ScannerError> {
    // Check content-type header first (cheap check before consuming body)
    let should_check = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase().contains("text/html"))
        .unwrap_or(false);

    if !should_check {
        return Ok(response);
    }

    // Consume the body to check for meta-refresh
    let body = response.text().await?;

    if let Some(redirect_url) = extract_meta_refresh(&body) {
        debug!("Following meta-refresh redirect to: {}", redirect_url);
        // Issue a fresh GET for the redirect URL
        let redirect_resp = client
            .get(&redirect_url)
            .send()
            .await
            .map_err(ScannerError::from)?;
        return Ok(redirect_resp);
    }

    // Body was consumed but no redirect — return it as a new response
    Ok(build_text_response(body))
}

/// Build a minimal HTTP response from a string body.
fn build_text_response(body: String) -> reqwest::Response {
    // reqwest::Response implements From<http::Response<Body>>
    let http_response = http::Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .body(body)
        .expect("Valid HTTP response");
    reqwest::Response::from(http_response)
}

// TODO: Fix regex quote handling
/// Extract redirect URL from meta-refresh tag in HTML.
fn extract_meta_refresh(html: &str) -> Option<String> {
    // Match <meta http-equiv="refresh" content="5;url=https://example.com/">
    // where the URL may or may not be quoted within the content attribute.
    let patterns = [
        // Pattern 1: url="..." or url='...' within content
        regex::Regex::new(
            r#"(?i)<meta\s+[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["']\d+\s*;\s*url\s*=\s*["']([^"']*)["'][^>]*>"#,
        )
        .ok()?,
        // Pattern 2: url=... without quotes within content
        regex::Regex::new(
            r#"(?i)<meta\s+[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["']\d+\s*;\s*url\s*=\s*([^"'\s>]+)"#,
        )
        .ok()?,
    ];

    for re in &patterns {
        if let Some(cap) = re.captures(html) {
            return Some(cap.get(1)?.as_str().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stealth_http_client_creation() {
        let client = StealthHttpClient::new(true, true, Some(Ja3Ja4Profile::Chrome), true)
            .expect("Should create client");
        assert!(client.client().get("https://example.com")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .is_ok());
    }

    #[tokio::test]
    async fn test_extract_meta_refresh() {
        let html = r#"<html><head><meta http-equiv="refresh" content="5;url=https://example.com/"></head><body></body></html>"#;
        let result = extract_meta_refresh(html);
        assert_eq!(result, Some("https://example.com/".to_string()));

        let html_no_meta = r#"<html><head><title>No redirect</title></head><body></body></html>"#;
        let result = extract_meta_refresh(html_no_meta);
        assert_eq!(result, None);
    }
}