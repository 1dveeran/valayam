use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

/// Performs a DNS lookup of the specified type and returns the results as strings.
///
/// # Arguments
/// * `domain` — The domain name to query.
/// * `query_type` — DNS record type: "A", "AAAA", "CNAME", "TXT", "MX".
///
/// # Returns
/// A vector of string representations of the DNS records found.
pub async fn resolve(domain: &str, query_type: &str) -> Vec<String> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    match query_type.to_uppercase().as_str() {
        "A" => {
            match resolver.ipv4_lookup(domain).await {
                Ok(lookup) => lookup.iter().map(|ip| ip.to_string()).collect(),
                Err(_) => Vec::new(),
            }
        }
        "AAAA" => {
            match resolver.ipv6_lookup(domain).await {
                Ok(lookup) => lookup.iter().map(|ip| ip.to_string()).collect(),
                Err(_) => Vec::new(),
            }
        }
        "CNAME" => {
            match resolver.lookup(domain, hickory_resolver::proto::rr::RecordType::CNAME).await {
                Ok(lookup) => lookup
                    .iter()
                    .filter_map(|r| r.as_cname().map(|c| c.to_string()))
                    .collect(),
                Err(_) => Vec::new(),
            }
        }
        "TXT" => {
            match resolver.txt_lookup(domain).await {
                Ok(lookup) => lookup
                    .iter()
                    .map(|txt| txt.to_string())
                    .collect(),
                Err(_) => Vec::new(),
            }
        }
        "MX" => {
            match resolver.mx_lookup(domain).await {
                Ok(lookup) => lookup
                    .iter()
                    .map(|mx| format!("{} {}", mx.preference(), mx.exchange()))
                    .collect(),
                Err(_) => Vec::new(),
            }
        }
        _ => {
            eprintln!("[!] Unsupported DNS query type: {}", query_type);
            Vec::new()
        }
    }
}
