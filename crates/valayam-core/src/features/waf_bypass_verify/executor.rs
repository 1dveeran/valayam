use crate::core::result::ScanResult;
use crate::network::http::StealthHttpClient;
use crate::template::schema::TemplateInfo;
use chrono::Utc;
use tracing::{debug, warn};
use super::parser::WafBypassVerifyTemplate;

// ---------------------------------------------------------------------------
// Structured WAF bypass techniques (const data)
// ---------------------------------------------------------------------------

/// A single WAF bypass technique with its metadata and payloads.
#[derive(Debug, Clone)]
struct BypassTechnique {
    /// Short unique name for the technique
    pub name: &'static str,
    /// Human-readable description of the technique
    pub description: &'static str,
    /// Severity if this technique bypasses the WAF
    pub severity: &'static str,
    /// CVSS score approximation
    pub cvss_score: f32,
    /// The set of payloads to test with this technique
    pub payloads: &'static [&'static str],
    /// Reference URL for more information
    pub reference: &'static str,
}

/// Standard attack payloads that WAFs are expected to block.
#[cfg_attr(not(test), allow(dead_code))]
const BASE_PAYLOADS: &[&str] = &[
    // XSS
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "';alert(1);//",
    // SQL Injection
    "' OR '1'='1",
    "' UNION SELECT * FROM users--",
    "1; DROP TABLE users--",
    // Path Traversal
    "../../etc/passwd",
    "..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    // Command Injection
    ";cat /etc/passwd",
    "|dir",
    "$(cat /etc/passwd)",
    // SSTI
    "{{7*7}}",
    "#{7*7}",
    // LDAP Injection
    "*)(uid=*))(|(uid=*",
    // NoSQL Injection
    "'||'1'=='1",
    "';return true;var foo='",
];

const TECHNIQUES: &[BypassTechnique] = &[
    // ---- Case manipulation ----
    BypassTechnique {
        name: "case-manipulation",
        description: "Mixed or altered letter casing to evade signature-based WAF detection",
        severity: "High",
        cvss_score: 7.0,
        reference: "https://owasp.org/www-community/attacks/xss/#evasion",
        payloads: &[
            "<ScRiPt>alert(1)</sCrIpT>",
            "<IMG SRC=x onerror=alert(1)>",
            "'Or'1'='1",
            "'UnIoN SeLeCt * FrOm users--",
            "<sCrIpt>alert(1)</SCript>",
        ],
    },
    // ---- URL encoding variations ----
    BypassTechnique {
        name: "url-encoding",
        description: "Single, double, and mixed URL encoding to evade WAF decoders",
        severity: "High",
        cvss_score: 7.5,
        reference: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Cheat_Sheet.html",
        payloads: &[
            // Single encoding
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "'%20OR%20'1'%3D'1",
            // Double encoding
            "%253Cscript%253Ealert(1)%253C/script%253E",
            "'%2520OR%2520'1'%253D'1",
            // Mixed encoding
            "%3Cscript%3Ealert%281%29%3C/script%3E",
            "'%20OR%20%27%31%27%3D%27%31",
            // Partial encoding
            "<scr%69pt>alert(1)</scr%69pt>",
        ],
    },
    // ---- Comment injection ----
    BypassTechnique {
        name: "comment-injection",
        description: "SQL and HTML comment insertion to break signature patterns",
        severity: "High",
        cvss_score: 7.5,
        reference: "https://portswigger.net/web-security/sql-injection",
        payloads: &[
            "'/**/OR/**/'1'='1",
            "'OR'1'='1'--",
            "'OR 1=1--",
            "'OR/**/1=1--",
            "'OR 1=1#",
            "1' ORDER BY 1--",
            "1' UNION/**/SELECT/**/1,2,3--",
            "<scr<!-->ipt>alert(1)</scr<!-->ipt>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<!--#exec cmd=\"cat /etc/passwd\"-->",
        ],
    },
    // ---- Parameter pollution ----
    BypassTechnique {
        name: "parameter-pollution",
        description: "HTTP Parameter Pollution (HPP) — multiple params with same name",
        severity: "High",
        cvss_score: 7.0,
        reference: "https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
        payloads: &[
            "q=1&q=<script>alert(1)</script>",
            "q=1&q='OR'1'='1",
            "q=safe&q=<script>alert(1)</script>",
            "q=<script>alert(1)</script>&q=safe",
        ],
    },
    // ---- Unicode / UTF-8 bypass ----
    BypassTechnique {
        name: "unicode-bypass",
        description: "Unicode and UTF-8 encoded characters to bypass normalization",
        severity: "Medium",
        cvss_score: 6.5,
        reference: "https://www.unicode.org/reports/tr36/",
        payloads: &[
            // UTF-8 overlong sequences
            "\u{FF1C}script\u{FF1E}alert(1)\u{FF1C}/script\u{FF1E}",
            // Fullwidth characters
            "\u{FF07}\u{FF2F}\u{FF32}\u{FF07}\u{FF18}\u{FF07}\u{FF1D}\u{FF07}\u{FF11}",
            // Combining marks
            "<scr\u{0301}ipt>alert(1)</scr\u{0301}ipt>",
            // Null byte prefix
            "\x00' OR '1'='1",
            // Unicode line separator
            "\u{2028}'OR 1=1--",
            // UTF-8 Bomb + payload
            "\u{FEFF}'OR'1'='1",
        ],
    },
    // ---- HTTP verb tampering ----
    BypassTechnique {
        name: "verb-tampering",
        description: "Alternative HTTP methods to bypass WAF rules that only inspect GET/POST",
        severity: "High",
        cvss_score: 7.5,
        reference: "https://owasp.org/www-community/attacks/HTTP_Verb_Tampering",
        payloads: &[
            // These will be sent as the HTTP method, not the body
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "OPTIONS",
            "HEAD",
            "CONNECT",
            "TRACE",
            "PROPFIND",
            "MOVE",
            "COPY",
            "MKCOL",
        ],
    },
    // ---- Header manipulation ----
    BypassTechnique {
        name: "header-manipulation",
        description: "Using X-Forwarded-For, X-Real-IP and other headers to bypass IP-based WAF rules",
        severity: "Medium",
        cvss_score: 5.0,
        reference: "https://portswigger.net/web-security/ssrf",
        payloads: &[
            "127.0.0.1",
            "localhost",
            "0.0.0.0",
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
        ],
    },
    // ---- Null byte injection ----
    BypassTechnique {
        name: "null-byte-injection",
        description: "Null byte (%00) injection to truncate strings and bypass backend parsers",
        severity: "High",
        cvss_score: 8.0,
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2006-7243",
        payloads: &[
            "<script>alert(1)</script>%00",
            "' OR '1'='1'%00",
            "../../etc/passwd%00",
            "script%00.js",
            "file%00.php?param=1",
        ],
    },
];

/// Returns `true` if the HTTP status code indicates a WAF block.
#[inline]
fn is_waf_block(status: u16) -> bool {
    matches!(status, 403 | 406 | 429 | 418 | 503)
}

/// Returns the HTTP method to use for verb tampering tests.
fn verb_tampering_method(payload: &str) -> &str {
    // For verb tampering technique, the payload IS the method name
    payload
}

// ---------------------------------------------------------------------------
// Public executor
// ---------------------------------------------------------------------------

pub async fn execute(
    target_host: &str,
    http_client: &StealthHttpClient,
    templates: &[WafBypassVerifyTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_host);

        // Phase 1: Establish baseline — send a benign request to confirm the target is reachable
        let baseline_url = host.trim_end_matches('/');
        match http_client.send_request("GET", baseline_url, None, None).await {
            Ok(base_resp) => {
                let base_status = base_resp.status().as_u16();
                debug!(target = %host, baseline_status = base_status, "WAF bypass baseline");
                if base_status >= 400 {
                    warn!(target = %host, status = base_status, "Target returned error on baseline request, skipping");
                    continue;
                }
            }
            Err(e) => {
                warn!(target = %host, error = %e, "WAF bypass baseline request failed");
                continue;
            }
        }

        // Phase 2: First test the original payloads with the standard query injection
        for payload in &template.payloads {
            let test_url = format!("{}/?q={}", host.trim_end_matches('/'), urlencoding::encode(payload));
            debug!(target = %host, payload = %payload, "Sending WAF baseline payload");

            match http_client.send_request("GET", &test_url, None, None).await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    if !is_waf_block(status) {
                        // WAF did not block the raw payload — this is a finding
                        return Some(ScanResult {
                            timestamp: Utc::now(),
                            template_id: template_id.to_string(),
                            template_name: template_info.name.clone(),
                            template_severity: "Critical".to_string(),
                            target: host.clone(),
                            payload: format!(
                                "Raw payload '{}' bypassed WAF (HTTP {}). No evasive mutation was needed.",
                                payload, status
                            ),
                            cvss_score: Some(8.0),
                            reference: Some("https://owasp.org/www-community/attacks/WAF_Evasion".to_string()),
                            solution: Some(
                                "Review WAF rules — the raw payload bypassed WAF filtering entirely.".to_string(),
                            ),
                            tags: vec!["waf-bypass".to_string(), "raw-payload".to_string()],
                            compliance: Default::default(),
                        });
                    }
                }
                Err(e) => {
                    tracing::trace!("WAF baseline request failed: {}", e);
                }
            }
        }

        // Phase 3: Test all structured bypass techniques
        let mut successful_bypasses: Vec<(String, String, f32)> = Vec::new(); // (technique_name, description, cvss)
        let mut worst_severity_rank: u8 = 0;
        let mut worst_severity_label: &str = "Info";

        for technique in TECHNIQUES {
            debug!(
                target = %host,
                technique = %technique.name,
                "Testing WAF bypass technique"
            );

            let is_verb_tampering = technique.name == "verb-tampering";
            let is_header_manipulation = technique.name == "header-manipulation";

            for raw_payload in technique.payloads {
                let mut additional_headers: Option<
                    std::collections::HashMap<String, String>,
                > = None;

                // Choose how to send the payload based on technique type
                let (method, url, body) = if is_verb_tampering {
                    // Verb tampering: use the payload string as the HTTP method
                    let method = verb_tampering_method(raw_payload);
                    let url = format!("{}/", host.trim_end_matches('/'));
                    (method.to_string(), url, None::<&str>)
                } else if is_header_manipulation {
                    // Header manipulation: send payload in X-Forwarded-For
                    let mut headers = std::collections::HashMap::new();
                    headers.insert("X-Forwarded-For".to_string(), raw_payload.to_string());
                    headers.insert("X-Real-IP".to_string(), raw_payload.to_string());
                    headers.insert("X-Originating-IP".to_string(), raw_payload.to_string());
                    additional_headers = Some(headers);
                    let url = format!("{}/", host.trim_end_matches('/'));
                    ("GET".to_string(), url, None::<&str>)
                } else if technique.name == "parameter-pollution" {
                    // Parameter pollution: payload already contains the full query string
                    let url = format!("{}/?{}", host.trim_end_matches('/'), raw_payload);
                    ("GET".to_string(), url, None::<&str>)
                } else {
                    // Standard: send as query parameter
                    let encoded = urlencoding::encode(raw_payload);
                    let url = format!("{}/?q={}", host.trim_end_matches('/'), encoded);
                    ("GET".to_string(), url, None::<&str>)
                };

                let headers_ref = additional_headers.as_ref();

                match http_client
                    .send_request(&method, &url, headers_ref, body.as_deref())
                    .await
                {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        if !is_waf_block(status) && status < 500 {
                            // Successfully bypassed with this technique
                            let rank = match technique.severity {
                                "Critical" => 5u8,
                                "High" => 4,
                                "Medium" => 3,
                                "Low" => 2,
                                _ => 1,
                            };
                            if rank > worst_severity_rank {
                                worst_severity_rank = rank;
                                worst_severity_label = technique.severity;
                            }
                            successful_bypasses.push((
                                technique.name.to_string(),
                                format!(
                                    "Technique '{}' bypassed WAF with payload '{}' (HTTP {})",
                                    technique.name, raw_payload, status
                                ),
                                technique.cvss_score,
                            ));
                            // Move to next technique (don't retry the same technique)
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::trace!(
                            "WAF bypass technique '{}' request failed: {}",
                            technique.name,
                            e
                        );
                    }
                }
            }
        }

        if successful_bypasses.is_empty() {
            debug!(target = %host, "No WAF bypass techniques succeeded");
            continue;
        }

        // --- Build result ---
        let worst_cvss = successful_bypasses
            .iter()
            .map(|(_, _, cvss)| *cvss)
            .fold(0.0f32, f32::max);

        let techniques_desc: Vec<String> = successful_bypasses
            .iter()
            .map(|(_, desc, _)| desc.clone())
            .collect();

        let techniques_used: Vec<String> = successful_bypasses
            .iter()
            .map(|(name, _, _)| name.clone())
            .collect();

        let payload = format!(
            "WAF Bypass Report: {} technique(s) evaded filtering:\n- {}",
            successful_bypasses.len(),
            techniques_desc.join("\n- "),
        );

        let solution = format!(
            "Update WAF rules to block the following techniques: {}.\
             Use positive security model and normalize input before inspection.",
            techniques_used.join(", ")
        );

        let reference =
            "https://owasp.org/www-community/attacks/WAF_Evasion".to_string();

        return Some(ScanResult {
            timestamp: Utc::now(),
            template_id: template_id.to_string(),
            template_name: format!("{} - WAF Bypass", template_info.name),
            template_severity: worst_severity_label.to_string(),
            target: host.clone(),
            payload,
            cvss_score: Some(worst_cvss),
            reference: Some(reference),
            solution: Some(solution),
            tags: {
                let mut t = vec!["waf-bypass".to_string(), format!("count:{}", successful_bypasses.len())];
                t.extend(techniques_used.into_iter().map(|n| format!("technique:{}", n)));
                t
            },
            compliance: {
                let mut m = std::collections::HashMap::new();
                m.insert("bypass-count".to_string(), successful_bypasses.len().to_string());
                m.insert(
                    "techniques".to_string(),
                    techniques_desc.join(", "),
                );
                m
            },
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_waf_block() {
        assert!(is_waf_block(403));
        assert!(is_waf_block(406));
        assert!(is_waf_block(429));
        assert!(is_waf_block(418));
        assert!(is_waf_block(503));
        assert!(!is_waf_block(200));
        assert!(!is_waf_block(301));
        assert!(!is_waf_block(404));
        assert!(!is_waf_block(500));
    }

    #[test]
    fn test_techniques_are_defined() {
        // Ensure all expected techniques are present
        let names: std::collections::HashSet<&str> = TECHNIQUES.iter().map(|t| t.name).collect();
        assert!(names.contains("case-manipulation"));
        assert!(names.contains("url-encoding"));
        assert!(names.contains("comment-injection"));
        assert!(names.contains("parameter-pollution"));
        assert!(names.contains("unicode-bypass"));
        assert!(names.contains("verb-tampering"));
        assert!(names.contains("header-manipulation"));
        assert!(names.contains("null-byte-injection"));
        assert_eq!(names.len(), 8, "Expected exactly 8 techniques");
    }

    #[test]
    fn test_each_technique_has_payloads() {
        for technique in TECHNIQUES {
            assert!(
                !technique.payloads.is_empty(),
                "Technique '{}' has no payloads",
                technique.name
            );
        }
    }

    #[test]
    fn test_verb_tampering_method() {
        assert_eq!(verb_tampering_method("POST"), "POST");
        assert_eq!(verb_tampering_method("PUT"), "PUT");
        assert_eq!(verb_tampering_method("OPTIONS"), "OPTIONS");
    }

    #[test]
    fn test_base_payloads_not_empty() {
        assert!(!BASE_PAYLOADS.is_empty());
        assert!(BASE_PAYLOADS.len() >= 10);
    }

    #[test]
    fn test_technique_unique_names() {
        let mut names: Vec<&str> = TECHNIQUES.iter().map(|t| t.name).collect();
        names.sort();
        let original_len = names.len();
        names.dedup();
        assert_eq!(names.len(), original_len, "Duplicate technique names found");
    }

    #[test]
    fn test_all_techniques_have_cvss() {
        for technique in TECHNIQUES {
            assert!(
                (0.0..=10.0).contains(&technique.cvss_score),
                "CVSS score {} for technique '{}' is out of range",
                technique.cvss_score,
                technique.name
            );
        }
    }
}