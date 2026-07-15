use std::collections::HashSet;
use reqwest::Client;

/// Automatically ingests indicators from external threat feeds.
pub struct FeedIngestor;

impl FeedIngestor {
    /// Fetches the CISA KEV (Known Exploited Vulnerabilities) catalog.
    pub async fn fetch_cisa_kev() -> Result<HashSet<String>, String> {
        let client = Client::new();
        // CISA KEV JSON endpoint
        let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
        
        let response = client.get(url).send().await.map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            let json_body: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
            let mut cves = HashSet::new();
            if let Some(vulns) = json_body.get("vulnerabilities").and_then(|v| v.as_array()) {
                for vuln in vulns {
                    if let Some(cve_id) = vuln.get("cveID").and_then(|id| id.as_str()) {
                        cves.insert(cve_id.to_string());
                    }
                }
            }
            tracing::info!("Successfully fetched CISA KEV catalog and extracted {} CVEs", cves.len());
            Ok(cves)
        } else {
            Err(format!("Failed to fetch CISA KEV: HTTP {}", response.status()))
        }
    }
}
