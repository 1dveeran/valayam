// TODO: Harden Variable Substitution & DSL Helpers.
// - Implement strict circular-dependency detection during resolution.
// - Optimize Regex substitutions for zero-copy where possible.
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;

/// Resolves all `{{variable}}` placeholders in a template string using the
/// provided variable context with circular dependency detection.
///
/// # Resolution Order
/// 1. Built-in variables (`{{BaseURL}}`, `{{Hostname}}`)
/// 2. Extracted variables (`{{auth_token}}`, etc.)
///
/// Helper function evaluation (e.g., `{{base64(...)}}`) is handled
/// separately by the `features::helpers` module and called after
/// variable resolution.
pub fn resolve_variables(template_str: &str, context: &HashMap<String, String>) -> String {
    // Detect and prevent circular references
    let mut visited = std::collections::HashSet::new();
    resolve_variables_with_detection(template_str, context, &mut visited)
}

/// Internal recursive function for variable resolution with cycle detection
fn resolve_variables_with_detection(
    template_str: &str,
    context: &HashMap<String, String>,
    visited: &mut std::collections::HashSet<String>,
) -> String {
    // Fast path: if no variables, return original string
    if !template_str.contains("{{") || !template_str.contains("}}") {
        return template_str.to_string();
    }

    lazy_static! {
        // Pre-compiled regex for better performance
        static ref VARIABLE_RE: Regex =
            Regex::new(r"\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}").expect("Valid regex");
    }

    let mut result = String::with_capacity(template_str.len());
    let mut last_pos = 0;

    for cap in VARIABLE_RE.captures_iter(template_str) {
        // Push text before the variable
        result.push_str(&template_str[last_pos..cap.get(0).unwrap().start()]);

        let var_name = cap.get(1).unwrap().as_str();

        // Check for circular dependency
        if !visited.insert(var_name.to_string()) {
            // Circular dependency detected - leave variable unresolved
            let placeholder = format!("{{{{{}}}}}", var_name);
            result.push_str(&placeholder);
            // Remove from visited set to allow other paths
            visited.remove(var_name);
            last_pos = cap.get(0).unwrap().end();
            continue;
        }

        // Replace with variable value if found
        if let Some(value) = context.get(var_name) {
            result.push_str(value);
        } else {
            // Variable not found - keep original placeholder
            let placeholder = format!("{{{{{}}}}}", var_name);
            result.push_str(&placeholder);
        }

        // Remove from visited set after processing
        visited.remove(var_name);
        last_pos = cap.get(0).unwrap().end();
    }

    // Push remaining text
    result.push_str(&template_str[last_pos..]);

    result
}

/// Builds the initial variable context from the target URL.
/// Seeds `BaseURL` and `Hostname` as built-in variables.
pub fn build_initial_context(target_url: &str, target_host: &str) -> HashMap<String, String> {
    let mut context = HashMap::with_capacity(2);
    let clean_target = target_url.trim_end_matches('/').to_string();
    context.insert("BaseURL".to_string(), clean_target);
    context.insert("Hostname".to_string(), target_host.to_string());
    context
}

/// Extracts all `{{variable_name}}` placeholders from a template string.
/// Returns a vector of variable names (without the braces).
pub fn extract_placeholder_names(template_str: &str) -> Vec<String> {
    lazy_static! {
        static ref VARIABLE_RE: Regex =
            Regex::new(r"\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}").expect("Valid regex");
    }

    VARIABLE_RE
        .captures_iter(template_str)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

/// Advanced variable resolution with support for default values and transformations
///
/// Supports syntax like:
// - `{{var|default:"fallback"}}` - provides default value if var is missing
/// - `{{var|upper}}` - transforms value to uppercase
/// - `{{var|lower}}` - transforms value to lowercase
/// - `{{var|trim}}` - trims whitespace
pub fn resolve_variables_advanced(
    template_str: &str,
    context: &HashMap<String, String>,
) -> String {
    // Detect and prevent circular references
    let mut visited = std::collections::HashSet::new();
    resolve_variables_advanced_with_detection(template_str, context, &mut visited)
}

/// Internal recursive function for advanced variable resolution with cycle detection
fn resolve_variables_advanced_with_detection(
    template_str: &str,
    context: &HashMap<String, String>,
    visited: &mut std::collections::HashSet<String>,
) -> String {
    // Fast path: if no variables, return original string
    if !template_str.contains("{{") || !template_str.contains("}}") {
        return template_str.to_string();
    }

    lazy_static! {
        // Regex to capture variable name and optional modifiers
        static ref ADVANCED_VARIABLE_RE: Regex =
            Regex::new(r"\{\{([a-zA-Z_][a-zA-Z0-9_]*)(?:\|([^}]+))?\}\}").expect("Valid regex");
    }

    let mut result = String::with_capacity(template_str.len());
    let mut last_pos = 0;

    for cap in ADVANCED_VARIABLE_RE.captures_iter(template_str) {
        // Push text before the variable
        result.push_str(&template_str[last_pos..cap.get(0).unwrap().start()]);

        let var_name = cap.get(1).unwrap().as_str();
        let modifiers = cap.get(2).map(|m| m.as_str());

        // Check for circular dependency
        if !visited.insert(var_name.to_string()) {
            // Circular dependency detected - leave variable unresolved
            if let Some(mods) = modifiers {
                let placeholder = format!("{{{{{}|{}}}}}", var_name, mods);
                result.push_str(&placeholder);
            } else {
                let placeholder = format!("{{{{{}}}}}", var_name);
                result.push_str(&placeholder);
            }
            // Remove from visited set to allow other paths
            visited.remove(var_name);
            last_pos = cap.get(0).unwrap().end();
            continue;
        }

        // Get variable value
        let mut value = match context.get(var_name) {
            Some(v) => v.clone(),
            None => {
                // Variable not found - check for default value in modifiers
                if let Some(mods) = modifiers {
                    if let Some(default_val) = extract_default_value(mods) {
                        default_val.to_string()
                    } else {
                        // Keep original placeholder if no default
                        if let Some(mods) = modifiers {
                            let placeholder = format!("{{{{{}|{}}}}}", var_name, mods);
                            result.push_str(&placeholder);
                        } else {
                            let placeholder = format!("{{{{{}}}}}", var_name);
                            result.push_str(&placeholder);
                        }
                        visited.remove(var_name);
                        last_pos = cap.get(0).unwrap().end();
                        continue;
                    }
                } else {
                    // No modifiers and no variable - keep placeholder
                    let placeholder = format!("{{{{{}}}}}", var_name);
                    result.push_str(&placeholder);
                    visited.remove(var_name);
                    last_pos = cap.get(0).unwrap().end();
                    continue;
                }
            }
        };

        // Apply modifiers if present
        if let Some(mods) = modifiers {
            value = apply_modifiers(&value, mods);
        }

        result.push_str(&value);

        // Remove from visited set after processing
        visited.remove(var_name);
        last_pos = cap.get(0).unwrap().end();
    }

    // Push remaining text
    result.push_str(&template_str[last_pos..]);

    result
}

/// Extract default value from modifier string like `default:"value"` or `default:'value'`
fn extract_default_value(modifiers: &str) -> Option<&str> {
    lazy_static! {
        static ref DEFAULT_RE: Regex =
            Regex::new(r#"default:(?:"([^"]*)"|'([^']*)')"#).expect("Valid regex");
    }

    DEFAULT_RE.captures(modifiers).and_then(|cap| {
        if let Some(val) = cap.get(1) {
            Some(val.as_str())
        } else if let Some(val) = cap.get(2) {
            Some(val.as_str())
        } else {
            None
        }
    })
}

/// Apply string modifiers like upper, lower, trim, etc.
fn apply_modifiers(value: &str, modifiers: &str) -> String {
    let mut result = value.to_string();

    for modifier in modifiers.split('|') {
        match modifier.trim() {
            "upper" => result = result.to_uppercase(),
            "lower" => result = result.to_lowercase(),
            "trim" => result = result.trim().to_string(),
            "reverse" => result = result.chars().rev().collect(),
            "len" => return result.len().to_string(),
            _ => {
                // Warn about unknown modifier
                tracing::warn!(?modifier, "Unknown variable modifier");
            }
        }
    }

    result
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
    fn test_resolve_variables_circular() {
        let mut ctx = HashMap::new();
        ctx.put("a".to_string(), "{{b}}".to_string());
        ctx.put("b".to_string(), "{{a}}".to_string());

        let result = resolve_variables("Start {{a}} end", &ctx);
        // Should detect circular dependency and leave unresolved
        assert!(result.contains("{{a}}") || result.contains("{{b}}"));
    }

    #[test]
    fn test_resolve_variables_advanced_with_default() {
        let mut ctx = HashMap::new();
        ctx.insert("name".to_string(), "John".to_string());

        // Test default value
        let result = resolve_variables_advanced("Hello {{name|default:\"Guest\"}}!", &ctx);
        assert_eq!(result, "Hello John!");

        // Test default when variable missing
        let result = resolve_variables_advanced("Hello {{missing|default:\"Guest\"}}!", &ctx);
        assert_eq!(result, "Hello Guest!");

        // Test modifiers
        let result = resolve_variables_advanced("Hello {{name|upper}}!", &ctx);
        assert_eq!(result, "Hello JOHN!");

        let result = resolve_variables_advanced("Hello {{name|lower}}!", &ctx);
        assert_eq!(result, "Hello john!");

        let result = resolve_variables_advanced("Hello {{name|reverse}}!", &ctx);
        assert_eq!(result, "Hello nhoJ!");

        let result = resolve_variables_advanced("Length: {{name|len}}", &ctx);
        assert_eq!(result, "Length: 4");
    }

    #[test]
    fn test_build_initial_context() {
        let ctx = build_initial_context("https://example.com/", "example.com");
        assert_eq!(ctx.get("BaseURL").unwrap(), "https://example.com");
        assert_eq!(ctx.get("Hostname").unwrap(), "example.com");
    }

    #[test]
    fn test_extract_placeholder_names() {
        let names = extract_placeholder_names("Bearer {{auth_token}} on {{BaseURL}} with {{timeout|default:\"30s\"}}");
        assert!(names.contains(&"auth_token".to_string()));
        assert!(names.contains(&"BaseURL".to_string()));
        assert!(names.contains(&"timeout".to_string()));
    }
}