use super::parser::Extractor;
use regex::Regex;
use std::collections::HashMap;

/// Extracts values from an HTTP response using the provided extractor rules.
///
/// Applies each extractor's regex against the appropriate response part
/// (body or headers) and returns a map of variable name → extracted value.
///
/// # Arguments
/// * `extractors` — The extractor rules from the template YAML.
/// * `body` — The raw response body bytes.
/// * `headers` — The response headers as a flat key-value map.
///
/// # Returns
/// A `HashMap<String, String>` of extracted variable names to their values.
/// Only successfully extracted values are included.
pub fn extract_from_response(
    extractors: &[Extractor],
    body: &[u8],
    headers: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut results = HashMap::new();
    let body_text = String::from_utf8_lossy(body);

    for extractor in extractors {
        if extractor.r#type != "regex" {
            eprintln!(
                "[!] Unsupported extractor type: '{}'. Skipping.",
                extractor.r#type
            );
            continue;
        }

        let Some(pattern) = &extractor.regex else {
            continue;
        };

        let Ok(re) = Regex::new(pattern) else {
            eprintln!(
                "[!] Invalid extractor regex for '{}': '{}'. Skipping.",
                extractor.name, pattern
            );
            continue;
        };

        // Determine the text to search based on the part field
        let search_text = match extractor.part.as_str() {
            "header" => {
                // Concatenate all headers into a single string for regex matching
                headers
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            _ => body_text.to_string(), // Default: search body
        };

        // Apply regex and extract the specified capture group
        if let Some(caps) = re.captures(&search_text) {
            if let Some(matched) = caps.get(extractor.group) {
                results.insert(extractor.name.clone(), matched.as_str().to_string());
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_from_body() {
        let extractors = vec![Extractor {
            r#type: "regex".to_string(),
            name: "token".to_string(),
            part: "body".to_string(),
            regex: Some(r#""token":\s*"([^"]+)""#.to_string()),
            group: 1,
        }];

        let body = br#"{"token": "abc123xyz"}"#;
        let headers = HashMap::new();

        let result = extract_from_response(&extractors, body, &headers);
        assert_eq!(result.get("token").unwrap(), "abc123xyz");
    }

    #[test]
    fn test_extract_from_header() {
        let extractors = vec![Extractor {
            r#type: "regex".to_string(),
            name: "session".to_string(),
            part: "header".to_string(),
            regex: Some(r"session=([^;]+)".to_string()),
            group: 1,
        }];

        let body = b"";
        let mut headers = HashMap::new();
        headers.insert(
            "Set-Cookie".to_string(),
            "session=s3cr3t_value; Path=/".to_string(),
        );

        let result = extract_from_response(&extractors, body, &headers);
        assert_eq!(result.get("session").unwrap(), "s3cr3t_value");
    }

    #[test]
    fn test_extract_no_match() {
        let extractors = vec![Extractor {
            r#type: "regex".to_string(),
            name: "missing".to_string(),
            part: "body".to_string(),
            regex: Some(r"not_here_(\d+)".to_string()),
            group: 1,
        }];

        let body = b"nothing matching";
        let headers = HashMap::new();

        let result = extract_from_response(&extractors, body, &headers);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_multiple() {
        let extractors = vec![
            Extractor {
                r#type: "regex".to_string(),
                name: "csrf".to_string(),
                part: "body".to_string(),
                regex: Some(r#"csrf_token=([a-f0-9]+)"#.to_string()),
                group: 1,
            },
            Extractor {
                r#type: "regex".to_string(),
                name: "user_id".to_string(),
                part: "body".to_string(),
                regex: Some(r#""user_id":\s*(\d+)"#.to_string()),
                group: 1,
            },
        ];

        let body = br#"csrf_token=deadbeef and "user_id": 42"#;
        let headers = HashMap::new();

        let result = extract_from_response(&extractors, body, &headers);
        assert_eq!(result.get("csrf").unwrap(), "deadbeef");
        assert_eq!(result.get("user_id").unwrap(), "42");
    }
}
