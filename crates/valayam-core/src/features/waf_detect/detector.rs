use crate::network::http::StealthHttpClient;

/// Known WAF fingerprint signatures mapped to their product names.
const WAF_SIGNATURES: &[(&str, &str)] = &[
    // Header-based fingerprints
    ("cf-ray", "Cloudflare"),
    ("cf-cache-status", "Cloudflare"),
    ("x-sucuri-id", "Sucuri"),
    ("x-sucuri-cache", "Sucuri"),
    ("x-cdn", "Incapsula/Imperva"),
    ("x-iinfo", "Incapsula/Imperva"),
    ("x-akamai-transformed", "Akamai"),
    ("x-amz-cf-id", "Amazon CloudFront"),
    ("x-amz-cf-pop", "Amazon CloudFront"),
    ("x-azure-ref", "Azure Front Door"),
    ("x-ms-ref", "Azure Front Door"),
    ("server-timing", "Fastly"),
    ("x-fw-hash", "F5 BIG-IP"),
    ("x-powered-by-plesk", "Plesk"),
    ("x-denied-reason", "WangZhanBao"),
    ("x-protected-by", "Generic WAF"),
];

/// Known WAF block page response body signatures.
const WAF_BODY_SIGNATURES: &[(&str, &str)] = &[
    ("attention required! | cloudflare", "Cloudflare"),
    ("sorry, you have been blocked", "Cloudflare"),
    ("access denied | incapsula", "Incapsula/Imperva"),
    ("request unsuccessful. incapsula", "Incapsula/Imperva"),
    ("this request was blocked by the security rules", "ModSecurity"),
    ("not acceptable!", "ModSecurity"),
    ("barracuda networks", "Barracuda WAF"),
    ("web application firewall", "Generic WAF"),
    ("are you a human?", "PerimeterX/HUMAN"),
    ("managed by citrix", "Citrix NetScaler"),
    ("fortiguard", "Fortinet FortiWeb"),
    ("ddos-guard", "DDoS-Guard"),
];

/// Detected WAF result with the product name and detection evidence.
#[derive(Debug, Clone)]
pub struct WafDetection {
    pub product: String,
    pub evidence: String,
}

/// Sends non-destructive probe requests to determine if a target uses a WAF
/// and identifies the WAF product via header and body fingerprinting.
pub async fn detect_waf(
    client: &StealthHttpClient,
    target_url: &str,
) -> Vec<WafDetection> {
    let mut detections = Vec::new();

    // Phase 1: Baseline request (clean GET) — check headers
    if let Ok(resp) = client.send_request("", "GET", target_url, None, None).await {
        let headers = resp.headers().clone();
        let body = resp.text().await.unwrap_or_default().to_lowercase();

        // Check response headers for WAF fingerprints
        for (header_name, waf_name) in WAF_SIGNATURES {
            if headers.contains_key(*header_name) {
                detections.push(WafDetection {
                    product: waf_name.to_string(),
                    evidence: format!("Header '{}' present in response", header_name),
                });
            }
        }

        // Check response body for WAF block page signatures
        for (signature, waf_name) in WAF_BODY_SIGNATURES {
            if body.contains(signature) {
                detections.push(WafDetection {
                    product: waf_name.to_string(),
                    evidence: format!("Body contains '{}'", signature),
                });
            }
        }

        // Check Server header for known WAF products
        if let Some(server) = headers.get("server") {
            let server_val = server.to_str().unwrap_or("").to_lowercase();
            if server_val.contains("cloudflare") {
                detections.push(WafDetection {
                    product: "Cloudflare".to_string(),
                    evidence: format!("Server header: {}", server_val),
                });
            } else if server_val.contains("akamaighost") || server_val.contains("akamai") {
                detections.push(WafDetection {
                    product: "Akamai".to_string(),
                    evidence: format!("Server header: {}", server_val),
                });
            } else if server_val.contains("awselb") || server_val.contains("awsalb") {
                detections.push(WafDetection {
                    product: "AWS ALB/ELB".to_string(),
                    evidence: format!("Server header: {}", server_val),
                });
            }
        }
    }

    // Phase 2: Trigger request (send known attack signature to provoke WAF block)
    let trigger_url = format!("{}?test=<script>alert(1)</script>&id=1%20OR%201=1", target_url);
    if let Ok(resp) = client.send_request("", "GET", &trigger_url, None, None).await {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default().to_lowercase();

        // WAF block status codes (403, 406, 429, 503)
        if matches!(status, 403 | 406 | 429 | 503) {
            // Check trigger body for WAF signatures
            for (signature, waf_name) in WAF_BODY_SIGNATURES {
                if body.contains(signature) {
                    detections.push(WafDetection {
                        product: waf_name.to_string(),
                        evidence: format!("Trigger probe blocked (status {}) with body match '{}'", status, signature),
                    });
                }
            }

            // If no specific product identified but blocked, flag generic WAF
            if detections.is_empty() {
                detections.push(WafDetection {
                    product: "Unknown WAF".to_string(),
                    evidence: format!("Trigger probe returned status {} (likely WAF block)", status),
                });
            }
        }
    }

    // Deduplicate by product name
    detections.sort_by(|a, b| a.product.cmp(&b.product));
    detections.dedup_by(|a, b| a.product == b.product);

    detections
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waf_signatures_not_empty() {
        assert!(!WAF_SIGNATURES.is_empty());
        assert!(!WAF_BODY_SIGNATURES.is_empty());
    }

    #[test]
    fn test_waf_detection_struct() {
        let det = WafDetection {
            product: "Cloudflare".to_string(),
            evidence: "cf-ray header present".to_string(),
        };
        assert_eq!(det.product, "Cloudflare");
        assert!(det.evidence.contains("cf-ray"));
    }
}
