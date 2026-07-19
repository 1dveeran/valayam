use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize)]
struct AlienVaultResponse {
    passive_dns: Vec<PassiveDnsEntry>,
}

#[derive(Deserialize)]
struct PassiveDnsEntry {
    hostname: String,
}

/// Query AlienVault OTX for subdomains of the given domain.
pub async fn enumerate_subdomains(client: &Client, domain: &str, max_results: usize) -> Result<Vec<String>, String> {
    let url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns", domain);
    
    let res = client.get(&url).send().await.map_err(|e| format!("Failed to request AlienVault: {}", e))?;
    if !res.status().is_success() {
        return Err(format!("AlienVault returned status: {}", res.status()));
    }

    let response: AlienVaultResponse = res.json().await.map_err(|e| format!("Failed to parse AlienVault JSON: {}", e))?;
    
    let mut subdomains = HashSet::new();
    for entry in response.passive_dns {
        let name = entry.hostname.trim().to_lowercase();
        if name.ends_with(domain) && !name.contains('*') {
            subdomains.insert(name);
        }
        if subdomains.len() >= max_results {
            break;
        }
    }

    Ok(subdomains.into_iter().take(max_results).collect())
}
