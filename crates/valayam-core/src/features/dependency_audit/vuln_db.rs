use serde::Deserialize;
use reqwest::Client;

#[derive(Debug, Deserialize)]
pub struct VulnRecord {
    pub cve_id: String,
    pub severity: String,
    pub description: Option<String>,
}

pub struct ApiVulnDb {
    api_url: String,
    client: Client,
}

impl ApiVulnDb {
    pub fn new(api_url: String, client: Client) -> Self {
        Self { api_url, client }
    }

    pub async fn check_package(&self, ecosystem: &str, package: &str, _version: &str) -> Vec<VulnRecord> {
        let mut vulns = Vec::new();
        // Option A: Call the external API
        if let Ok(reqwest_url) = reqwest::Url::parse(&self.api_url) {
            if let Ok(resp) = self.client.get(reqwest_url)
                .query(&[("ecosystem", ecosystem), ("package", package)])
                // .query(&[("version", _version)]) // Can add exact version later
                .send()
                .await
            {
                if let Ok(results) = resp.json::<Vec<VulnRecord>>().await {
                    vulns = results;
                }
            }
        }
        vulns
    }
}

pub struct LocalVulnDb {
    #[allow(dead_code)]
    db_path: String,
}

impl LocalVulnDb {
    pub fn new(db_path: String) -> Self {
        Self { db_path }
    }

    pub fn check_package(&self, _ecosystem: &str, _package: &str, _version: &str) -> Vec<VulnRecord> {
        // Option B: Local DB was using sqlite, removed to keep core stateless.
        // In an enterprise setup, this would load a JSON/CSV index into memory or use the API.
        tracing::warn!("LocalVulnDb sqlite backend has been deprecated. Please use ApiVulnDb.");
        Vec::new()
    }
}
