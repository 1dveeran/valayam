use regex::Regex;
use std::collections::HashSet;

/// Extracts API routes, paths, and URLs from a JavaScript bundle string.
/// Uses heuristic regex patterns to locate endpoints, React/Vue routing paths,
/// and relative URLs.
pub fn extract_js_endpoints(js_content: &str) -> HashSet<String> {
    let mut endpoints = HashSet::new();

    // Regex to match relative endpoints like /api/v1/... or /users/...
    // Also matches websocket schemas
    let path_regex = Regex::new(
        r#"(?:"|')((?:/[a-zA-Z0-9_\-\.\?\,\'\/\+&\$#\=~\|\!]*){2,})(?:"|')"#
    ).unwrap();

    // Regex to match full URL patterns including ws/wss
    let url_regex = Regex::new(
        r#"(https?|wss?|grpc)://[a-zA-Z0-9_\-\.:/\?&\$#\=~\|]+"#
    ).unwrap();

    // Extract relative paths
    for cap in path_regex.captures_iter(js_content) {
        if let Some(matched) = cap.get(1) {
            let val = matched.as_str();
            // Filter out common false positives (e.g. file extensions, double slashes, formatting)
            if !val.contains("//") && !val.ends_with(".js") && !val.ends_with(".css") && !val.ends_with(".png") && val.len() > 2 {
                endpoints.insert(val.to_string());
            }
        }
    }

    // Extract absolute URLs
    for cap in url_regex.captures_iter(js_content) {
        if let Some(matched) = cap.get(0) {
            endpoints.insert(matched.as_str().to_string());
        }
    }

    endpoints
}

/// Extracts common query parameter keys and JSON payload keys from Javascript bundles.
pub fn extract_js_parameters(js_content: &str) -> HashSet<String> {
    let mut params = HashSet::new();

    // 1. Match query parameter names (e.g. ?limit=10, &page=2)
    let query_param_regex = Regex::new(r#"[?&]([a-zA-Z0-9_\-]+)="#).unwrap();
    for cap in query_param_regex.captures_iter(js_content) {
        if let Some(matched) = cap.get(1) {
            params.insert(matched.as_str().to_string());
        }
    }

    // 2. Match JSON keys or object properties (e.g. "username": or 'password': )
    let object_key_regex = Regex::new(r#"(?:"|')([a-zA-Z0-9_\-]+)(?:"|')\s*:"#).unwrap();
    for cap in object_key_regex.captures_iter(js_content) {
        if let Some(matched) = cap.get(1) {
            params.insert(matched.as_str().to_string());
        }
    }

    // Filter out common javascript builtins/keywords to keep parameters clean
    let ignore_words = ["default", "name", "type", "id", "true", "false", "null", "undefined", "const", "let", "var", "function", "return", "class", "import", "export"];
    params.retain(|p| !ignore_words.contains(&p.as_str()) && !p.is_empty());

    params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_js_endpoints() {
        let js = r#"
            const api = "/api/v1/users";
            fetch('/api/v2/posts?limit=10');
            const ws = "wss://localhost:8080/stream";
            let path = "/dashboard/settings";
        "#;
        let res = extract_js_endpoints(js);
        assert!(res.contains("/api/v1/users"));
        assert!(res.contains("/api/v2/posts?limit=10"));
        assert!(res.contains("/dashboard/settings"));
        assert!(res.contains("wss://localhost:8080/stream"));
    }

    #[test]
    fn test_extract_js_parameters() {
        let js = r#"
            const params = {
                "username": "admin",
                'password': "123",
                "csrf_token": "token"
            };
            fetch('/api/search?q=rust&limit=5');
        "#;
        let res = extract_js_parameters(js);
        assert!(res.contains("username"));
        assert!(res.contains("password"));
        assert!(res.contains("csrf_token"));
        assert!(res.contains("q"));
        assert!(res.contains("limit"));
        assert!(!res.contains("default"));
    }
}
