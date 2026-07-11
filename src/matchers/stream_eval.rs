use regex::bytes::Regex;
use std::sync::LazyLock;

// Modern Rust Feature: LazyLock compiles these heavy regexes exactly ONCE
// at runtime, making them thread-safe and instantly available to all async workers.
static SENSITIVE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"root:x:[0-9]+:[0-9]+:").unwrap(),
        Regex::new(r"(?i)DB_PASSWORD=").unwrap(),
        Regex::new(r#"\"args\":\s*\{"#).unwrap(), // Matches httpbin.org payload reflection
    ]
});

pub struct ModernMatcher;

impl ModernMatcher {
    /// Evaluates raw byte slices without allocating expensive String copies in memory
    pub fn evaluate_stream(body_bytes: &[u8], customized_patterns: &[String]) -> bool {
        // 1. Fast global check (Zero-Day indicators hardcoded in engine)
        for re in SENSITIVE_PATTERNS.iter() {
            if re.is_match(body_bytes) {
                return true;
            }
        }

        // 2. Custom template check (from the YAML file)
        for pattern in customized_patterns {
            // Modern let-else: if the user wrote a bad regex, skip it safely
            let Ok(re) = Regex::new(pattern) else {
                continue;
            };
            if re.is_match(body_bytes) {
                return true;
            }
        }

        false
    }
}
