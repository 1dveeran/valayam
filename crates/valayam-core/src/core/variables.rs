use regex::Regex;
use std::collections::HashMap;

/// Resolves all `{{variable}}` placeholders in a template string using the
/// provided variable context.
///
/// # Resolution Order
/// 1. Built-in variables (`{{BaseURL}}`, `{{Hostname}}`)
/// 2. Extracted variables (`{{auth_token}}`, etc.)
///
/// Helper function evaluation (e.g., `{{base64(...)}}`) is handled
/// separately by the `features::helpers` module and called after
/// variable resolution.
pub fn resolve_variables(template_str: &str, context: &HashMap<String, String>) -> String {
    let mut result = template_str.to_string();
    for (key, value) in context {
        let placeholder = format!("{{{{{}}}}}", key); // {{key}}
        result = result.replace(&placeholder, value);
    }
    result
}

/// Builds the initial variable context from the target URL.
/// Seeds `BaseURL` and `Hostname` as built-in variables.
pub fn build_initial_context(target_url: &str, target_host: &str) -> HashMap<String, String> {
    let mut context = HashMap::new();
    let clean_target = target_url.trim_end_matches('/').to_string();
    context.insert("BaseURL".to_string(), clean_target);
    context.insert("Hostname".to_string(), target_host.to_string());
    context
}

/// Extracts all `{{variable_name}}` placeholders from a template string.
/// Returns a vector of variable names (without the braces).
pub fn extract_placeholder_names(template_str: &str) -> Vec<String> {
    let re = Regex::new(r"\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}").unwrap();
    re.captures_iter(template_str)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_variables_basic() {
        let mut ctx = HashMap::new();
        ctx.insert("BaseURL".to_string(), "https://example.com".to_string());
        ctx.insert("token".to_string(), "abc123".to_string());

        let result = resolve_variables("{{BaseURL}}/api?t={{token}}", &ctx);
        assert_eq!(result, "https://example.com/api?t=abc123");
    }

    #[test]
    fn test_resolve_variables_no_match() {
        let ctx = HashMap::new();
        let result = resolve_variables("no placeholders here", &ctx);
        assert_eq!(result, "no placeholders here");
    }

    #[test]
    fn test_resolve_variables_missing_key() {
        let ctx = HashMap::new();
        let result = resolve_variables("{{missing_var}}", &ctx);
        assert_eq!(result, "{{missing_var}}"); // Unresolved stays as-is
    }

    #[test]
    fn test_build_initial_context() {
        let ctx = build_initial_context("https://example.com/", "example.com");
        assert_eq!(ctx.get("BaseURL").unwrap(), "https://example.com");
        assert_eq!(ctx.get("Hostname").unwrap(), "example.com");
    }

    #[test]
    fn test_extract_placeholder_names() {
        let names = extract_placeholder_names("Bearer {{auth_token}} on {{BaseURL}}");
        assert!(names.contains(&"auth_token".to_string()));
        assert!(names.contains(&"BaseURL".to_string()));
    }
}
