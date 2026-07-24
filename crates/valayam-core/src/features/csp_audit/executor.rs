use valayam_models::finding::FindingOwned;
use crate::network::http::StealthHttpClient;
use valayam_models::TemplateMetadata;
use lazy_static::lazy_static;
use regex::Regex;
use scraper::{Html, Selector};
use std::collections::HashMap;
use tracing::{debug, warn};
use valayam_models::templates::csp_audit::CspAuditTemplate;

// ---------------------------------------------------------------------------
// CSP directive knowledge base (const data, no runtime mutability)
// ---------------------------------------------------------------------------

/// Describes a single CSP directive check that should be performed.
#[derive(Debug, Clone)]
struct CspDirectiveCheck {
    /// The CSP directive name, e.g. "script-src"
    pub directive: &'static str,
    /// Human-readable description of what is being checked
    pub label: &'static str,
    /// Severity if this directive is missing entirely (None = skip)
    pub severity_if_missing: Option<&'static str>,
    /// CVSS if the directive is missing
    pub cvss_if_missing: Option<f32>,
    /// Severity if the directive contains a weak keyword (wildcard, unsafe-inline, etc.)
    pub severity_if_weak: Option<&'static str>,
    /// CVSS if weak keyword is found
    pub cvss_if_weak: Option<f32>,
    /// Weak patterns that trigger a finding inside the directive value
    pub weak_patterns: &'static [&'static str],
    /// Exempting patterns that cancel the finding (e.g. nonce-/sha256- for script-src)
    pub exempting_patterns: &'static [&'static str],
    /// CWE identifier
    pub cwe: &'static str,
    /// Remediation advice
    pub solution: &'static str,
    /// Reference URL
    pub reference: &'static str,
}

const DIRECTIVE_CHECKS: &[CspDirectiveCheck] = &[
    // ---- script-src ----
    CspDirectiveCheck {
        directive: "script-src",
        label: "script-src allows unsafe inline scripts or has wildcard sources",
        severity_if_missing: Some("Medium"),
        cvss_if_missing: Some(5.0),
        severity_if_weak: Some("Critical"),
        cvss_if_weak: Some(9.0),
        weak_patterns: &["*", "'unsafe-inline'", "'unsafe-eval'"],
        exempting_patterns: &["'nonce-", "'sha256-", "'sha384-", "'sha512-"],
        cwe: "CWE-79",
        solution: "Specify strict script-src: use nonces or hashes instead of 'unsafe-inline'. Avoid wildcards.",
        reference: "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    },
    // ---- object-src ----
    CspDirectiveCheck {
        directive: "object-src",
        label: "object-src is missing or allows all sources (plugins enabled)",
        severity_if_missing: Some("High"),
        cvss_if_missing: Some(7.0),
        severity_if_weak: Some("High"),
        cvss_if_weak: Some(7.0),
        weak_patterns: &["*"],
        exempting_patterns: &["'none'"],
        cwe: "CWE-1024",
        solution: "Set object-src 'none' to disable plugin execution (Flash, Java applets).",
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/object-src",
    },
    // ---- base-uri ----
    CspDirectiveCheck {
        directive: "base-uri",
        label: "base-uri is not restricted (open to base tag injection)",
        severity_if_missing: Some("Medium"),
        cvss_if_missing: Some(5.0),
        severity_if_weak: Some("Medium"),
        cvss_if_weak: Some(5.0),
        weak_patterns: &["*"],
        exempting_patterns: &["'none'", "'self'"],
        cwe: "CWE-20",
        solution: "Restrict base-uri to 'self' or a specific origin to prevent base tag injection.",
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/base-uri",
    },
    // ---- frame-ancestors (clickjacking) ----
    CspDirectiveCheck {
        directive: "frame-ancestors",
        label: "frame-ancestors is missing (vulnerable to clickjacking)",
        severity_if_missing: Some("Medium"),
        cvss_if_missing: Some(6.0),
        severity_if_weak: Some("Medium"),
        cvss_if_weak: Some(6.0),
        weak_patterns: &["*"],
        exempting_patterns: &["'none'", "'self'"],
        cwe: "CWE-1021",
        solution: "Add frame-ancestors 'self' or 'none' to prevent clickjacking attacks.",
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
    },
    // ---- form-action ----
    CspDirectiveCheck {
        directive: "form-action",
        label: "form-action is not restricted (forms can submit to any origin)",
        severity_if_missing: Some("Low"),
        cvss_if_missing: Some(4.0),
        severity_if_weak: Some("Low"),
        cvss_if_weak: Some(4.0),
        weak_patterns: &["*"],
        exempting_patterns: &["'self'", "'none'"],
        cwe: "CWE-345",
        solution: "Restrict form-action to 'self' or a specific endpoint to limit form submission targets.",
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/form-action",
    },
    // ---- upgrade-insecure-requests ----
    CspDirectiveCheck {
        directive: "upgrade-insecure-requests",
        label: "upgrade-insecure-requests is missing (mixed content not auto-upgraded)",
        severity_if_missing: Some("Medium"),
        cvss_if_missing: Some(4.0),
        severity_if_weak: None,   // directive has no value to be weak
        cvss_if_weak: None,
        weak_patterns: &[],
        exempting_patterns: &[],
        cwe: "CWE-319",
        solution: "Add 'upgrade-insecure-requests' directive to automatically upgrade HTTP resources to HTTPS.",
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/upgrade-insecure-requests",
    },
    // ---- block-all-mixed-content ----
    CspDirectiveCheck {
        directive: "block-all-mixed-content",
        label: "block-all-mixed-content is missing",
        severity_if_missing: Some("Low"),
        cvss_if_missing: Some(3.0),
        severity_if_weak: None,
        cvss_if_weak: None,
        weak_patterns: &[],
        exempting_patterns: &[],
        cwe: "CWE-319",
        solution: "Add 'block-all-mixed-content' directive to prevent mixed content loading.",
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/block-all-mixed-content",
    },
];

impl CspDirectiveCheck {
    /// Returns `true` when the directive value contains any of the exempting patterns.
    fn is_exempted(&self, value: &str) -> bool {
        self.exempting_patterns
            .iter()
            .any(|p| value.contains(p))
    }

    /// Returns `true` when the directive value contains a weak pattern.
    fn has_weak_pattern(&self, value: &str) -> bool {
        self.weak_patterns
            .iter()
            .any(|p| value.contains(p))
    }
}

/// Severity ordering for picking the worst finding.
fn severity_rank(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// CSP parsing helpers
// ---------------------------------------------------------------------------

lazy_static! {
    /// Matches a CSP meta tag: <meta http-equiv="Content-Security-Policy" content="...">
    static ref META_CSP_HTTP_EQUIV: Regex = Regex::new(
        r#"(?i)<meta\s[^>]*http-equiv\s*=\s*['"]content-security-policy['"][^>]*>"#
    )
    .expect("Valid CSP meta-tag regex");
}

/// Parse a single CSP header value into a map of directive -> value string.
/// Directives are separated by `;`, each directive has `name value1 value2 ...`.
fn parse_csp(csp_str: &str) -> HashMap<String, String> {
    let mut directives: HashMap<String, String> = HashMap::new();
    for part in csp_str.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Split on the first whitespace to separate directive name from its value(s)
        if let Some(pos) = trimmed.find(char::is_whitespace) {
            let name = trimmed[..pos].trim().to_lowercase();
            let value = trimmed[pos + 1..].trim().to_string();
            if !name.is_empty() {
                directives.insert(name, value);
            }
        } else {
            // directive without a value (e.g. `block-all-mixed-content`)
            directives.insert(trimmed.to_lowercase(), String::new());
        }
    }
    directives
}

/// Extract CSP strings from HTML meta tags (http-equiv = Content-Security-Policy).
fn extract_csp_from_meta(html: &str) -> Vec<String> {
    let mut results = Vec::new();
    let document = Html::parse_document(html);

    // Try a case-insensitive attribute selector; `i` flag may fail in older cssparser,
    // so we fall back to a broad selector and filter manually.
    let selector_str = "meta[http-equiv='Content-Security-Policy']";
    if let Ok(selector) = Selector::parse(selector_str) {
        for element in document.select(&selector) {
            if let Some(content) = element.value().attr("content") {
                results.push(content.to_string());
            }
        }
    }

    // Also catch lowercase http-equiv via manual regex (broader catch-all).
    for cap in META_CSP_HTTP_EQUIV.captures_iter(html) {
        let full_tag = cap.get(0).map(|m| m.as_str()).unwrap_or("");
        // Extract content attribute
        if let Some(content) = extract_meta_content(full_tag) {
            if !results.iter().any(|r| r == content) {
                results.push(content.to_string());
            }
        }
    }

    results
}

/// Extract the `content` attribute value from a <meta> tag snippet.
fn extract_meta_content(meta_tag: &str) -> Option<&str> {
    lazy_static! {
        static ref CONTENT_RE: Regex = Regex::new(
            r#"content\s*=\s*(?:"([^"]*)"|'([^']*)')"#
        )
        .expect("Valid content attribute regex");
    }
    CONTENT_RE.captures(meta_tag).and_then(|cap| {
        cap.get(1).or_else(|| cap.get(2)).map(|m| m.as_str())
    })
}

// ---------------------------------------------------------------------------
// Public executor
// ---------------------------------------------------------------------------

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[CspAuditTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        let reqwest_url = match reqwest::Url::parse(&host) {
            Ok(u) => u,
            Err(e) => {
                warn!(target = %host, error = %e, "Failed to parse target URL for CSP audit");
                continue;
            }
        };

        let req_client = client.client();
        let resp = match req_client.get(reqwest_url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(target = %host, error = %e, "CSP audit request failed");
                continue;
            }
        };

        // --- Collect CSP strings from headers ---
        let header_csp: Vec<String> = resp
            .headers()
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .into_iter()
            .collect();

        // Also check for Content-Security-Policy-Report-Only
        let report_only_csp: Vec<String> = resp
            .headers()
            .get("content-security-policy-report-only")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .into_iter()
            .collect();

        // --- Collect CSP strings from meta tags ---
        let body_bytes = match resp.bytes().await {
            Ok(b) => b.to_vec(),
            Err(e) => {
                warn!(target = %host, error = %e, "Failed to read CSP audit response body");
                // Continue with header-only analysis
                Vec::new()
            }
        };
        let body_str = String::from_utf8_lossy(&body_bytes);
        let meta_csp = extract_csp_from_meta(&body_str);

        let all_csp_strings: Vec<String> = header_csp
            .into_iter()
            .chain(report_only_csp)
            .chain(meta_csp)
            .collect();

        debug!(
            target = %host,
            csp_count = all_csp_strings.len(),
            "CSP sources found"
        );

        if all_csp_strings.is_empty() {
            // No CSP at all — this is itself a finding
            let mut finding = FindingOwned::from_template_and_info(
                template_id,
                template_meta,
                host.clone(),
                "Content Security Policy (CSP) header is missing entirely. \
                 The application is vulnerable to XSS and data injection attacks \
                 without a defense-in-depth layer."
                    .to_string(),
            );
            finding.severity = "High".to_string();
            finding.solution = Some(
                "Implement a Content Security Policy using the strictest possible directives."
                    .to_string(),
            );
            finding.metadata.insert("::cvss_score".to_string(), "8.0".to_string());
            finding.metadata.insert("::reference".to_string(), "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP".to_string());
            finding.metadata.insert("::tags".to_string(), "csp,missing-header".to_string());
            finding.metadata.insert("owasp".to_string(), "OWASP-XXE-1".to_string());
            finding.metadata.insert("cwe".to_string(), "CWE-693".to_string());
            finding.metadata.insert("severity".to_string(), "High (CVSS: 8.0)".to_string());
            return Some(finding);
        }

        // --- Analyse each CSP string ---
        let mut findings: Vec<(String, String, f32)> = Vec::new(); // (label, cwe, cvss)
        let mut worst_severity: u8 = 0;
        let mut worst_severity_label = "Info".to_string();

        for csp_str in &all_csp_strings {
            let directives = parse_csp(csp_str);

            for check in DIRECTIVE_CHECKS {
                match directives.get(check.directive) {
                    None => {
                        // Directive is missing entirely
                        if let Some(sev) = check.severity_if_missing {
                            if let Some(cvss) = check.cvss_if_missing {
                                let rank = severity_rank(sev);
                                if rank > worst_severity {
                                    worst_severity = rank;
                                    worst_severity_label = sev.to_string();
                                }
                                findings.push((
                                    format!(
                                        "Missing '{}' directive — {}",
                                        check.directive, check.label
                                    ),
                                    check.cwe.to_string(),
                                    cvss,
                                ));
                            }
                        }
                    }
                    Some(val) => {
                        // Directive present; check for weak patterns
                        if check.is_exempted(val) {
                            continue; // Exempted (e.g. script-src with a nonce)
                        }
                        if check.has_weak_pattern(val) {
                            if let Some(sev) = check.severity_if_weak {
                                if let Some(cvss) = check.cvss_if_weak {
                                    let rank = severity_rank(sev);
                                    if rank > worst_severity {
                                        worst_severity = rank;
                                        worst_severity_label = sev.to_string();
                                    }
                                    let weak_keywords: Vec<&str> = check
                                        .weak_patterns
                                        .iter()
                                        .filter(|p| val.contains(*p))
                                        .copied()
                                        .collect();
                                    findings.push((
                                        format!(
                                            "'{}' directive contains weak keyword(s) {:?} — {}",
                                            check.directive, weak_keywords, check.label
                                        ),
                                        check.cwe.to_string(),
                                        cvss,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        if findings.is_empty() {
            debug!(target = %host, "CSP audit passed — no weak directives detected");
            continue;
        }

        // --- Build the result payload ---
        let csp_source_info = if all_csp_strings.len() == 1 {
            "1 CSP source".to_string()
        } else {
            format!("{} CSP sources", all_csp_strings.len())
        };

        let payload_lines: Vec<String> = findings
            .iter()
            .map(|(label, cwe, cvss)| {
                format!("[{}] (CVSS: {:.1}) {}", cwe, cvss, label)
            })
            .collect();

        let payload = format!(
            "CSP Audit found {} issue(s) across {}:\n{}",
            findings.len(),
            csp_source_info,
            payload_lines.join("\n"),
        );

        // Get the worst CVSS score
        let worst_cvss = findings
            .iter()
            .map(|(_, _, cvss)| *cvss)
            .fold(0.0f32, f32::max);

        let solution = "Review each CSP directive highlighted above. Use strict directives: \
                        script-src with nonces/hashes, object-src 'none', base-uri 'self', \
                        frame-ancestors 'self', form-action 'self', and add \
                        upgrade-insecure-requests together with block-all-mixed-content."
            .to_string();

        let reference =
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP".to_string();

        let cwe_set: std::collections::BTreeSet<&str> = findings
            .iter()
            .map(|(_, cwe, _)| cwe.as_str())
            .collect();
        let cwe_list: Vec<&str> = cwe_set.into_iter().collect();

        let tags_list = {
            let mut t = vec!["csp".to_string()];
            t.push(format!("finding-count:{}", findings.len()));
            t.join(",")
        };
        let mut finding = FindingOwned::from_template_and_info(
            template_id,
            template_meta,
            host.clone(),
            payload,
        );
        finding.severity = worst_severity_label;
        finding.solution = Some(solution);
        finding.metadata.insert("::cvss_score".to_string(), worst_cvss.to_string());
        finding.metadata.insert("::reference".to_string(), reference);
        finding.metadata.insert("::tags".to_string(), tags_list);
        finding.metadata.insert("csp-issues".to_string(), findings.len().to_string());
        finding.metadata.insert("cwe".to_string(), cwe_list.join(", "));
        return Some(finding);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csp_basic() {
        let csp = "default-src 'self'; script-src 'self' 'nonce-abc123'; object-src 'none'";
        let map = parse_csp(csp);
        assert_eq!(map.get("default-src").unwrap(), "'self'");
        assert_eq!(map.get("script-src").unwrap(), "'self' 'nonce-abc123'");
        assert_eq!(map.get("object-src").unwrap(), "'none'");
    }

    #[test]
    fn test_parse_csp_directive_without_value() {
        let csp = "upgrade-insecure-requests; block-all-mixed-content";
        let map = parse_csp(csp);
        assert!(map.contains_key("upgrade-insecure-requests"));
        assert!(map.contains_key("block-all-mixed-content"));
        assert_eq!(map.get("upgrade-insecure-requests").unwrap(), "");
    }

    #[test]
    fn test_parse_csp_case_normalization() {
        let csp = "Script-Src 'self'; BASE-uri 'none'";
        let map = parse_csp(csp);
        assert!(map.contains_key("script-src"));
        assert!(map.contains_key("base-uri"));
    }

    #[test]
    fn test_has_weak_pattern_unsafe_inline() {
        let check = &DIRECTIVE_CHECKS[0]; // script-src
        assert!(check.has_weak_pattern("'self' 'unsafe-inline'"));
        assert!(check.has_weak_pattern("'unsafe-eval'"));
        assert!(!check.has_weak_pattern("'self' 'nonce-xyz'"));
    }

    #[test]
    fn test_is_exempted_nonce() {
        let check = &DIRECTIVE_CHECKS[0]; // script-src
        assert!(check.is_exempted("'self' 'nonce-abc123'"));
        assert!(check.is_exempted("'sha256-xyz'"));
        assert!(!check.is_exempted("'self' 'unsafe-inline'"));
    }

    #[test]
    fn test_parse_csp_empty() {
        let map = parse_csp("");
        assert!(map.is_empty());

        let map = parse_csp("   ; ;;  ");
        assert!(map.is_empty());
    }

    #[test]
    fn test_extract_meta_content_double_quotes() {
        let tag = r#"<meta http-equiv="Content-Security-Policy" content="default-src 'self'">"#;
        assert_eq!(
            extract_meta_content(tag),
            Some("default-src 'self'")
        );
    }

    #[test]
    fn test_extract_meta_content_single_quotes() {
        let tag = "<meta http-equiv='Content-Security-Policy' content='default-src self'>";
        assert_eq!(extract_meta_content(tag), Some("default-src self"));
    }

    #[test]
    fn test_severity_rank() {
        assert_eq!(severity_rank("Critical"), 5);
        assert_eq!(severity_rank("High"), 4);
        assert_eq!(severity_rank("Medium"), 3);
        assert_eq!(severity_rank("Low"), 2);
        assert_eq!(severity_rank("Info"), 1);
        assert_eq!(severity_rank("unknown"), 0);
    }

    #[test]
    fn test_default_src_not_restricted() {
        // default-src * is not in DIRECTIVE_CHECKS directly but the
        // individual directives should cover it.  This test verifies
        // that a minimal parse works.
        let map = parse_csp("default-src *");
        assert_eq!(map.get("default-src").unwrap(), "*");
    }

    #[test]
    fn test_all_directives_checked() {
        // Ensure every expected directive has a check entry
        let checked: std::collections::HashSet<&str> = DIRECTIVE_CHECKS
            .iter()
            .map(|c| c.directive)
            .collect();
        assert!(checked.contains("script-src"));
        assert!(checked.contains("object-src"));
        assert!(checked.contains("base-uri"));
        assert!(checked.contains("frame-ancestors"));
        assert!(checked.contains("form-action"));
        assert!(checked.contains("upgrade-insecure-requests"));
        assert!(checked.contains("block-all-mixed-content"));
    }

    #[test]
    fn test_strict_csp_has_no_findings() {
        let csp = "default-src 'self'; script-src 'self' 'nonce-abc123'; \
                    object-src 'none'; base-uri 'self'; frame-ancestors 'self'; \
                    form-action 'self'; upgrade-insecure-requests; block-all-mixed-content";
        let directives = parse_csp(csp);
        let mut findings = 0;
        for check in DIRECTIVE_CHECKS {
            match directives.get(check.directive) {
                None => {
                    if check.severity_if_missing.is_some() {
                        findings += 1;
                    }
                }
                Some(val) => {
                    if check.is_exempted(val) {
                        continue;
                    }
                    if check.has_weak_pattern(val) {
                        findings += 1;
                    }
                }
            }
        }
        assert_eq!(findings, 0, "Strict CSP should have zero findings");
    }
}