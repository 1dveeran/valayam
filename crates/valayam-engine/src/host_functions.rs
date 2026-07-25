use extism::host_fn;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::Resolver;
use std::fs;
use std::path::PathBuf;

host_fn!(pub dns_resolve(user_data: (); domain: String) -> String {
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(5);
    opts.attempts = 1;

    let resolver = match Resolver::new(ResolverConfig::default(), opts) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to create DNS resolver in host fn");
            return Ok("[]".to_string());
        }
    };

    let mut ips = Vec::new();
    if let Ok(response) = resolver.ipv4_lookup(&domain) {
        for addr in response.iter() {
            ips.push(addr.0.to_string());
        }
    }
    
    if let Ok(response) = resolver.ipv6_lookup(&domain) {
        for addr in response.iter() {
            ips.push(addr.0.to_string());
        }
    }

    Ok(serde_json::to_string(&ips).unwrap_or_else(|_| "[]".to_string()))
});

host_fn!(pub kv_get(user_data: (); key: String) -> String {
    let state_dir = PathBuf::from(".valayam-state");
    let file_path = state_dir.join(&key);
    
    if file_path.exists() {
        if let Ok(content) = fs::read_to_string(file_path) {
            return Ok(content);
        }
    }
    Ok("".to_string())
});

host_fn!(pub kv_set(user_data: (); input: String) -> String {
    let state_dir = PathBuf::from(".valayam-state");
    let _ = fs::create_dir_all(&state_dir);
    
    // input is JSON: {"key": "foo", "value": "bar"}
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&input) {
        if let Some(key) = json.get("key").and_then(|v| v.as_str()) {
            if let Some(value) = json.get("value").and_then(|v| v.as_str()) {
                let file_path = state_dir.join(key);
                let _ = fs::write(file_path, value);
                return Ok("ok".to_string());
            }
        }
    }
    Ok("error".to_string())
});
