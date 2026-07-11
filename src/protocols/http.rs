use reqwest::{Client, Method};
use std::collections::HashMap;
use std::time::Duration;

pub struct StealthHttpClient {
    client: Client,
}

impl StealthHttpClient {
    pub fn new() -> Result<Self, crate::core::error::ScannerError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true) // Required to scan internal targets using self-signed certs
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
            .build()?;

        Ok(Self { client })
    }

    pub async fn send_request(
        &self,
        base_url: &str,
        method_str: &str,
        resolved_path_or_url: &str,
        custom_headers: Option<&HashMap<String, String>>,
    ) -> Result<reqwest::Response, crate::core::error::ScannerError> {
        let Ok(method) = Method::from_bytes(method_str.as_bytes()) else {
            return Err(crate::core::error::ScannerError::InvalidHttpMethod(method_str.to_string()));
        };

        // Modern URL Assembly: Dynamically detect and handle both relative and absolute paths
        let full_url = if resolved_path_or_url.starts_with("http://")
            || resolved_path_or_url.starts_with("https://")
        {
            resolved_path_or_url.to_string()
        } else {
            let base = base_url.trim_end_matches('/');
            let path = resolved_path_or_url.trim_start_matches('/');
            format!("{}/{}", base, path)
        };

        let mut req_builder = self.client.request(method, &full_url);

        if let Some(headers) = custom_headers {
            for (key, val) in headers {
                req_builder = req_builder.header(key, val);
            }
        }

        let response = req_builder.send().await?;
        Ok(response)
    }
}
