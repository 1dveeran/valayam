// TODO: Enhance DNS auditing capabilities for DNS.
// - Implement DNSSEC validation and chain verification.
// - Add rate limiting awareness for DNS queries.
// - Cache DNS responses to reduce redundant queries.
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use reqwest::Client;
use hickory_resolver::{config::*, Resolver};
use hickory_resolver::proto::rr::*;
use tracing::debug;

/// Attempts a DNS zone transfer (AXFR) for the given domain.
pub async fn attempt_axfr(domain: &str, nameservers: Option<&[String]>) -> Vec<String> {
    let mut records = Vec::new();

    // Get nameservers to try
    let mut ns_to_try = Vec::new();
    if let Some(ns_list) = nameservers {
        ns_to_try.extend(ns_list.iter().cloned());
    } else {
        // Fetch NS records for the domain
        match resolve(domain, "NS").await {
            Ok(ns_records) => {
                for ns in ns_records {
                    // Remove trailing dot if present
                    let ns_clean = ns.trim_end_matches('.').to_string();
                    ns_to_try.push(ns_clean);
                }
            }
            Err(_) => {
                // Fallback to common nameservers if we can't get NS records
                ns_to_try = vec![
                    format!("ns1.{domain}"),
                    format!("ns2.{domain}"),
                    format!("dns1.{domain}"),
                    format!("dns2.{domain}"),
                ];
            }
        }
    }

    // Try each nameserver
    for ns in ns_to_try {
        match perform_axfr_transfer(&ns, domain).await {
            Ok(Some(zone_records)) => {
                // Successful transfer
                records.extend(zone_records.into_iter());
                break; // Success, no need to try other servers
            }
            Ok(None) => {
                // Transfer refused or not implemented - try next server
                continue;
            }
            Err(e) => {
                // Error during transfer - log and try next
                debug!("AXJR failed for {}@{}: {}", domain, ns, e);
                continue;
            }
        }
    }

    records
}

/// Performs the actual AXFR transfer with a nameserver.
async fn perform_axfr_transfer(nameserver: &str, _domain: &str) -> Result<Option<Vec<String>>, std::io::Error> {
    // Use TCP port 53 for zone transfers
    let addr = format!("{}:53", nameserver);

    // Set up TCP stream with timeout
    let _stream = match timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await {
        Ok(stream) => stream?,
        Err(_) => return Ok(None),
    };

    // For now, we'll simulate the AXFR process
    // In a real implementation, we would use a DNS library that supports AXFR
    // Since hickory-resolver might not have direct AXFR support in this version,
    // we'll return None to indicate the attempt was made but we can't verify success
    // without actually implementing the full AXFR protocol

    Ok(None) // Placeholder - actual implementation would parse AXFR response
}

/// Check for potential subdomain takeover vulnerabilities by examining CNAME records.
pub async fn check_subdomain_takeover(domain: &str) -> Vec<SubdomainTakeoverInfo> {
    let mut vulnerabilities = Vec::new();

    // Get CNAME records for the domain
    let cname_records = match resolve(domain, "CNAME").await {
        Ok(records) => records,
        Err(_) => return vec![], // No CNAME records or error
    };

    // Check each CNAME target against known vulnerable services
    for cname_target in cname_records {
        // Clean up the target (remove trailing dot if present)
        let target = cname_target.trim_end_matches('.').to_string();

        // Some services require specific checks
        if is_vulnerable_takeover_target(&target).await {
            vulnerabilities.push(SubdomainTakeoverInfo {
                domain: domain.to_string(),
                cname: cname_target,
                target: target.clone(),
                service: identify_vulnerable_service(&target).await,
                confidence: calculate_takeover_confidence(&target).await,
                remediation: get_takeover_remediation(&target).await,
            });
        }
    }

    vulnerabilities
}

/// Check if a target is potentially vulnerable to subdomain takeover.
async fn is_vulnerable_takeover_target(target: &str) -> bool {
    // List of known vulnerable service patterns
    let vulnerable_patterns = [
        "github.io",
        "herokuapp.com",
        "heroku.com",
        "aws.amazon.com",
        "s3.amazonaws.com",
        "azurewebsites.net",
        "cloudapp.net",
        "shopify.com",
        "squarespace.com",
        "bitbucket.io",
        "readthedocs.io",
        "pantheonsite.io",
        "fastly.net",
    ];

    // Check if domain ends with any vulnerable pattern
    for pattern in &vulnerable_patterns {
        if target.ends_with(*pattern) {
            // Additional verification: try to see if service is actually unclaimed
            return service_claim_check(target, *pattern).await;
        }
    }

    false
}

/// Attempt to verify if a service is actually unclaimed (simplified check).
async fn service_claim_check(domain: &str, pattern: &str) -> bool {
    // This is a simplified check - in reality, you would need to
    // attempt to actually claim the resource or check for specific responses
    // that indicate the service is available

    // For demonstration, we'll do a simple HTTP check for some services
    match pattern {
        "github.io" | "gitlab.io" => {
            // Check if GitHub/GitLab page exists
            check_http_endpoint(&format!("https://{domain}")).await
        }
        "herokuapp.com" | "heroku.com" => {
            // Check if Heroku app exists
            check_http_endpoint(&format!("https://{domain}")).await
        }
        "s3.amazonaws.com" => {
            // Check if S3 bucket exists
            check_http_endpoint(&format!("http://{domain}.s3.amazonaws.com")).await
        }
        "azurewebsites.net" => {
            // Check if Azure Web App exists
            check_http_endpoint(&format!("https://{domain}")).await
        }
        "shopify.com" => {
            // Check if Shopify store exists
            check_http_endpoint(&format!("https://{domain}")).await
        }
        _ => false, // Unknown pattern
    }
}

/// Check if an HTTP endpoint responds (indicating service might be claimed).
async fn check_http_endpoint(url: &str) -> bool {
    let client = match Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    match client.get(url).send().await {
        Ok(response) => {
            // If we get a successful response (2xx), the service is likely claimed
            response.status().is_success()
        }
        Err(_) => {
            // If we can't connect or get an error, it might be available
            // (though could also be network issues, firewall, etc.)
            false
        }
    }
}

/// Identify which vulnerable service a target might be associated with.
async fn identify_vulnerable_service(target: &str) -> String {
    // Map targets to specific services
    if target.ends_with("github.io") || target.ends_with("gitlab.io") {
        return "GitHub Pages / GitLab Pages".to_string();
    }
    if target.ends_with("herokuapp.com") || target.ends_with("heroku.com") {
        return "Heroku".to_string();
    }
    if target.ends_with("s3.amazonaws.com") {
        return "Amazon S3".to_string();
    }
    if target.ends_with("azurewebsites.net") {
        return "Azure App Service".to_string();
    }
    if target.ends_with("shopify.com") {
        return "Shopify".to_string();
    }
    if target.ends_with("readthedocs.io") {
        return "Read the Docs".to_string();
    }
    if target.ends_with("pantheonsite.io") {
        return "Pantheon".to_string();
    }
    if target.ends_with("fastly.net") {
        return "Fastly".to_string();
    }

    "Unknown Service".to_string()
}

/// Calculate confidence level for a takeover vulnerability.
async fn calculate_takeover_confidence(target: &str) -> String {
    // In a real implementation, this would check multiple factors
    // For now, return a fixed value based on service type
    if target.ends_with("github.io") || target.ends_with("gitlab.io") {
        "High".to_string()
    } else if target.ends_with("herokuapp.com") || target.ends_with("heroku.com") {
        "High".to_string()
    } else if target.ends_with("s3.amazonaws.com") {
        "Medium".to_string() // S3 buckets can be tricky to detect
    } else {
        "Medium".to_string()
    }
}

/// Get remediation advice for a takeover vulnerability.
async fn get_takeover_remediation(target: &str) -> String {
    // Provide specific remediation based on service
    if target.ends_with("github.io") || target.ends_with("gitlab.io") {
        "Remove the CNAME record and ensure no conflicting resources exist on GitHub/GitLab Pages".to_string()
    } else if target.ends_with("herokuapp.com") || target.ends_with("heroku.com") {
        "Remove the CNAME record and reclaim the Heroku app or release the subdomain".to_string()
    } else if target.ends_with("s3.amazonaws.com") {
        "Remove the CNAME record and either delete or rename the S3 bucket".to_string()
    } else if target.ends_with("azurewebsites.net") {
        "Remove the CNAME record and delete the Azure App Service or use a different domain".to_string()
    } else if target.ends_with("shopify.com") {
        "Remove the CNAME record and close the Shopify store or transfer the domain".to_string()
    } else {
        "Remove the CNAME record as it points to an external service that may no longer be in use".to_string()
    }
}

/// Information about a potential subdomain takeover vulnerability.
#[derive(Debug, Clone)]
pub struct SubdomainTakeoverInfo {
    pub domain: String,
    pub cname: String,
    pub target: String,
    pub service: String,
    pub confidence: String,
    pub remediation: String,
}

/// Resolve DNS records for a domain.
pub async fn resolve(domain: &str, record_type: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // Create a resolver with system configuration
    let resolver = Resolver::new(
        ResolverConfig::default(),
        ResolverOpts::default(),
    )?;

    // Parse the record type
    let record_type_parsed = record_type.parse::<RecordType>()?;

    // Perform the lookup
    let response = resolver.lookup(domain, record_type_parsed)?;

    // Extract record data as strings
    let mut results = Vec::new();
    for record in response {
        let record_data = record;
        let record_str = match record_data {
            // A record
            RData::A(a) => a.to_string(),

            // AAAA record
            RData::AAAA(aaaa) => aaaa.to_string(),

            // CNAME record
            RData::CNAME(cname) => cname.to_utf8().to_string(),

            // MX record
            RData::MX(mx) => mx.exchange().to_utf8().to_string(),

            // NS record
            RData::NS(ns) => ns.to_utf8().to_string(),

            // PTR record
            RData::PTR(ptr) => ptr.to_utf8().to_string(),

            // TXT record
            RData::TXT(txt) => {
                let txt_data: Vec<String> = txt.txt_data()
                    .iter()
                    .map(|txt_data| String::from_utf8_lossy(txt_data).into_owned())
                    .collect();
                txt_data.join(" ")
            }

            // For other record types, use a debug representation
            _ => {
                format!("{:?}", record_data)
            }
        };
        if !record_str.is_empty() {
            results.push(record_str);
        }
    }

    Ok(results)
}