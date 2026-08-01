// WASM-only: host function bindings supplied by the Extism runtime.
// Non-WASM builds (e.g. Windows test/dev) use stub implementations.

#[cfg(target_arch = "wasm32")]
#[extism_pdk::host_fn]
extern "ExtismHost" {
    pub fn dns_resolve(domain: String) -> String;
    pub fn kv_get(key: String) -> String;
    pub fn kv_set(input: String) -> String;
}

#[cfg(not(target_arch = "wasm32"))]
pub mod _stubs {
    use std::net::ToSocketAddrs;
    pub fn dns_resolve(domain: String) -> String {
        let result: Vec<String> = (domain.as_str(), 0)
            .to_socket_addrs()
            .ok()
            .into_iter()
            .flatten()
            .map(|a| a.ip().to_string())
            .collect();
        serde_json::to_string(&result).unwrap_or_else(|_| "[]".into())
    }
}

#[cfg(target_arch = "wasm32")]
fn dns_resolve_fallback(domain: &str) -> Option<Vec<String>> {
    let res = unsafe { dns_resolve(domain.to_string()) };
    if let Ok(json) = res {
        if let Ok(ips) = serde_json::from_str::<Vec<String>>(&json) {
            return Some(ips);
        }
    }
    None
}

#[cfg(not(target_arch = "wasm32"))]
fn dns_resolve_fallback(domain: &str) -> Option<Vec<String>> {
    let json = _stubs::dns_resolve(domain.to_string());
    serde_json::from_str::<Vec<String>>(&json).ok().filter(|v| !v.is_empty())
}

pub fn resolve_dns(domain: &str) -> Option<Vec<String>> {
    dns_resolve_fallback(domain)
}

#[cfg(target_arch = "wasm32")]
fn kv_get_fallback(key: &str) -> Option<String> {
    let res = unsafe { kv_get(key.to_string()) };
    if let Ok(content) = res {
        if !content.is_empty() {
            return Some(content);
        }
    }
    None
}

#[cfg(not(target_arch = "wasm32"))]
fn kv_get_fallback(_key: &str) -> Option<String> {
    None
}

pub fn get_state(key: &str) -> Option<String> {
    kv_get_fallback(key)
}

#[cfg(target_arch = "wasm32")]
fn kv_set_fallback(key: &str, value: &str) -> bool {
    let json = format!(r#"{{"key":"{}","value":"{}"}}"#, key, value);
    let res = unsafe { kv_set(json) };
    if let Ok(status) = res {
        return status == "ok";
    }
    false
}

#[cfg(not(target_arch = "wasm32"))]
fn kv_set_fallback(_key: &str, _value: &str) -> bool {
    false
}

pub fn set_state(key: &str, value: &str) -> bool {
    kv_set_fallback(key, value)
}