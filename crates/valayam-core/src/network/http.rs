// TODO: Enhance StealthHttpClient for WAF Evasion.
// - Integrate JA3/JA4 TLS spoofing at the `reqwest`/`rustls` layer.
// - Add logic to detect and transparently follow meta-refreshes.
use reqwest::{Client, Method, Proxy};
use std::collections::HashMap;
use std::time::Duration;
use std::sync::Arc;
use crate::stealth::user_agent::random_user_agent;
use crate::stealth::proxy::ProxyRotator;

#[derive(Clone)]
pub struct StealthHttpClient {
    clients: Vec<Client>,
    random_agent: bool,
    client_idx: Arc<std::sync::atomic::AtomicUsize>,
}

impl StealthHttpClient {
    pub fn new(random_agent: bool, proxy_rotator: Option<ProxyRotator>) -> Result<Self, crate::core::error::ScannerError> {
        let mut clients = Vec::new();

        if let Some(rotator) = proxy_rotator {
            for proxy_url in rotator.proxies.iter() {
                let mut builder = Client::builder()
                    .timeout(Duration::from_secs(15))
                    .connect_timeout(Duration::from_secs(5))
                    .pool_idle_timeout(Duration::from_secs(90))
                    .pool_max_idle_per_host(50)
                    .tcp_keepalive(Duration::from_secs(60))
                    .danger_accept_invalid_certs(true);
                
                if !random_agent {
                    builder = builder.user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");
                }
                
                if let Ok(proxy) = Proxy::all(proxy_url) {
                    builder = builder.proxy(proxy);
                }

                if let Ok(client) = builder.build() {
                    clients.push(client);
                }
            }
        }

        if clients.is_empty() {
            let mut builder = Client::builder()
                .timeout(Duration::from_secs(15))
                .connect_timeout(Duration::from_secs(5))
                .pool_idle_timeout(Duration::from_secs(90))
                .pool_max_idle_per_host(100)
                .tcp_keepalive(Duration::from_secs(60))
                .danger_accept_invalid_certs(true);
                
            if !random_agent {
                builder = builder.user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");
            }
            
            clients.push(builder.build()?);
        }

        Ok(Self { 
            clients, 
            random_agent,
            client_idx: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    pub fn get_client(&self) -> &Client {
        let idx = self.client_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.clients.len();
        &self.clients[idx]
    }

    /// Sends an HTTP request with optional body and custom headers.
    #[tracing::instrument(skip(self, custom_headers, body))]
    pub async fn send_request(
        &self,
        base_url: &str,
        method_str: &str,
        resolved_path_or_url: &str,
        custom_headers: Option<&HashMap<String, String>>,
        body: Option<&str>,
    ) -> Result<reqwest::Response, crate::core::error::ScannerError> {
        let Ok(method) = Method::from_bytes(method_str.as_bytes()) else {
            return Err(crate::core::error::ScannerError::InvalidHttpMethod(method_str.to_string()));
        };

        let full_url = if resolved_path_or_url.starts_with("http://")
            || resolved_path_or_url.starts_with("https://")
        {
            resolved_path_or_url.to_string()
        } else {
            let base = base_url.trim_end_matches('/');
            let path = resolved_path_or_url.trim_start_matches('/');
            format!("{}/{}", base, path)
        };

        let client = self.get_client();
        let mut req_builder = client.request(method, &full_url);

        if self.random_agent {
            req_builder = req_builder.header("User-Agent", random_user_agent());
        }

        if let Some(headers) = custom_headers {
            for (key, val) in headers {
                req_builder = req_builder.header(key, val);
            }
        }

        if let Some(body_str) = body {
            req_builder = req_builder.body(body_str.to_string());
        }

        let response = req_builder.send().await?;
        Ok(response)
    }
}
