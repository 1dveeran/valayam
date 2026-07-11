use regex::Regex;
use rhai::{Dynamic, Engine, ImmutableString, Map, Scope};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// A sandboxed Rhai scripting environment that exposes safe HTTP and regex
/// capabilities to executed scripts. Designed for multi-step scan workflows
/// that the YAML DSL alone cannot express (e.g., login → extract token → inject).
///
/// # Safety Model
/// - CPU-bounded: `max_operations` prevents infinite loops.
/// - Memory-bounded: `max_string_size`, `max_array_size`, `max_map_size` cap allocations.
/// - Stack-bounded: `max_call_levels` prevents deep recursion.
/// - No filesystem or process access is registered — scripts can only call
///   the explicitly whitelisted functions below.
pub struct ScriptEngine {
    engine: Engine,
}

/// Builds a `reqwest::blocking::Client` on a dedicated OS thread so that its
/// internal tokio runtime doesn't conflict with the outer async runtime.
/// The client is returned as an `Arc` for sharing across registered Rhai closures.
fn build_blocking_client(
) -> Result<Arc<reqwest::blocking::Client>, crate::core::error::ScannerError> {
    let handle = std::thread::spawn(|| {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
            .build()
    });

    let client = handle.join().map_err(|_| {
        crate::core::error::ScannerError::ScriptEngineInitError(
            "Failed to spawn client builder thread".to_string(),
        )
    })??;

    Ok(Arc::new(client))
}

impl ScriptEngine {
    /// Constructs a new sandboxed script engine with safety limits and
    /// registered HTTP/regex/log functions.
    pub fn new() -> Result<Self, crate::core::error::ScannerError> {
        let mut engine = Engine::new();

        // ── Safety Limits ───────────────────────────────────────────
        engine.set_max_operations(100_000); // CPU cap per eval
        engine.set_max_string_size(1_048_576); // 1 MB max string
        engine.set_max_array_size(1_000); // max array elements
        engine.set_max_map_size(500); // max map entries
        engine.set_max_call_levels(16); // max recursion depth

        // ── Blocking HTTP Client (built off-runtime) ────────────────
        let http_client = build_blocking_client()?;

        // ── Register: http_get(url) → Map { status, body, headers } ──
        let client_get = Arc::clone(&http_client);
        engine.register_fn("http_get", move |url: ImmutableString| -> Dynamic {
            perform_http_request(&client_get, "GET", url.as_str(), None)
        });

        // ── Register: http_post(url, body) → Map { status, body, headers } ──
        let client_post = Arc::clone(&http_client);
        engine.register_fn(
            "http_post",
            move |url: ImmutableString, body: ImmutableString| -> Dynamic {
                perform_http_request(&client_post, "POST", url.as_str(), Some(body.as_str()))
            },
        );

        // ── Register: regex_match(text, pattern) → bool ──
        engine.register_fn(
            "regex_match",
            |text: ImmutableString, pattern: ImmutableString| -> bool {
                let Ok(re) = Regex::new(pattern.as_str()) else {
                    return false;
                };
                re.is_match(text.as_str())
            },
        );

        // ── Register: regex_capture(text, pattern) → string ──
        // Returns the first capture group, or empty string if no match.
        engine.register_fn(
            "regex_capture",
            |text: ImmutableString, pattern: ImmutableString| -> ImmutableString {
                let Ok(re) = Regex::new(pattern.as_str()) else {
                    return ImmutableString::new();
                };
                let Some(caps) = re.captures(text.as_str()) else {
                    return ImmutableString::new();
                };
                let Some(matched) = caps.get(1) else {
                    return ImmutableString::new();
                };
                matched.as_str().into()
            },
        );

        // ── Register: log(message) ──
        engine.register_fn("log", |msg: ImmutableString| {
            println!("[script] {}", msg);
        });

        Ok(Self { engine })
    }

    /// Executes a Rhai script with pre-injected variables.
    ///
    /// # Arguments
    /// * `script_source` — The Rhai source code string to evaluate.
    /// * `variables` — Key-value pairs injected into the script's scope
    ///   (e.g., `target_url`, `base_url`, `hostname`).
    ///
    /// # Returns
    /// `Ok(true)` if the script evaluates to a truthy `Dynamic` value,
    /// indicating a finding. `Ok(false)` otherwise. `Err` on script errors.
    pub fn execute(
        &self,
        script_source: &str,
        variables: &BTreeMap<String, String>,
    ) -> Result<bool, crate::core::error::ScannerError> {
        let mut scope = Scope::new();

        // Inject all provided variables into the Rhai scope
        for (key, value) in variables {
            scope.push(key.clone(), value.clone());
        }

        let result: Dynamic = self
            .engine
            .eval_with_scope(&mut scope, script_source)
            .map_err(|e| crate::core::error::ScannerError::ScriptExecutionError(e.to_string()))?;

        // Coerce the script's return value to a boolean finding signal
        Ok(result.as_bool().unwrap_or(false))
    }
}

/// Internal helper: performs a blocking HTTP request on a fresh OS thread
/// and returns the result as a Rhai-compatible `Dynamic::Map`.
///
/// **Important:** `reqwest::blocking` panics if called from a thread that has a
/// tokio runtime guard. We escape this by running the actual request on a
/// fresh `std::thread` with no async context.
fn perform_http_request(
    client: &reqwest::blocking::Client,
    method: &str,
    url: &str,
    body: Option<&str>,
) -> Dynamic {
    let client = client.clone();
    let method = method.to_string();
    let url = url.to_string();
    let body = body.map(|b| b.to_string());

    let handle = std::thread::spawn(move || {
        let request = match method.as_str() {
            "POST" => {
                let mut req = client.post(&url);
                if let Some(b) = &body {
                    req = req
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .body(b.clone());
                }
                req
            }
            _ => client.get(&url),
        };

        let Ok(response) = request.send() else {
            return error_map("Connection failed");
        };

        let status = response.status().as_u16() as i64;

        // Build a flat header map for script access
        let mut header_map = Map::new();
        for (key, value) in response.headers() {
            let Ok(val_str) = value.to_str() else {
                continue;
            };
            header_map.insert(key.as_str().into(), Dynamic::from(val_str.to_string()));
        }

        let Ok(body_text) = response.text() else {
            return error_map("Failed to read response body");
        };

        let mut result = Map::new();
        result.insert("status".into(), Dynamic::from(status));
        result.insert("body".into(), Dynamic::from(body_text));
        result.insert("headers".into(), Dynamic::from(header_map));

        Dynamic::from(result)
    });

    handle
        .join()
        .unwrap_or_else(|_| error_map("Request thread panicked"))
}

/// Builds an error response map that scripts can inspect.
fn error_map(message: &str) -> Dynamic {
    let mut result = Map::new();
    result.insert("status".into(), Dynamic::from(0_i64));
    result.insert("body".into(), Dynamic::from(String::new()));
    result.insert("error".into(), Dynamic::from(message.to_string()));
    Dynamic::from(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_script_regex_match() {
        let engine = ScriptEngine::new().unwrap();
        let script = r#"
            regex_match("test-string-123", "string-[0-9]+")
        "#;
        let vars = BTreeMap::new();
        let result = engine.execute(script, &vars).unwrap();
        assert!(result, "Regex match should return true");
    }

    #[test]
    fn test_script_infinite_loop_limit() {
        let engine = ScriptEngine::new().unwrap();
        // This script tries to run forever
        let script = r#"
            let x = 0;
            loop { x += 1; }
        "#;
        let vars = BTreeMap::new();
        let result = engine.execute(script, &vars);
        // The max_operations limit should kill it and return an error, NOT hang the test
        assert!(
            result.is_err(),
            "Script should have been terminated by max_operations limit"
        );
    }
}
