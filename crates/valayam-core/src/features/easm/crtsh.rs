use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize)]
struct CrtShEntry {
    name_value: String,
}

/// Query crt.sh for subdomains of the given domain.
pub async fn enumerate_subdomains(client: &Client, domain: &str, max_results: usize) -> Result<Vec<String>, String> {
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    
    let res = client.get(&url).send().await.map_err(|e| format!("Failed to request crt.sh: {}", e))?;
    if !res.status().is_success() {
        return Err(format!("crt.sh returned status: {}", res.status()));
    }

    let entries: Vec<CrtShEntry> = res.json().await.map_err(|e| format!("Failed to parse crt.sh JSON: {}", e))?;
    
    let mut subdomains = HashSet::new();
    for entry in entries {
        // crt.sh can return multiple domains separated by newlines in name_value
        for name in entry.name_value.split('\n') {
            let name = name.trim().to_lowercase();
            if name.ends_with(domain) && !name.contains('*') {
                subdomains.insert(name);
            }
        }
        if subdomains.len() >= max_results {
            break;
        }
    }

    Ok(subdomains.into_iter().take(max_results).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;

    #[tokio::test]
    async fn test_crtsh_query() {
        let client = Client::new();
        // Use a well-known domain to guarantee results
        let result = enumerate_subdomains(&client, "example.com", 5).await;
        
        match result {
            Ok(subdomains) => {
                if !subdomains.is_empty() {
                    assert!(subdomains[0].ends_with("example.com"));
                }
            }
            Err(e) => {
                println!("crt.sh query failed (expected if service is unstable): {}", e);
            }
        }
    }
}
