// We must declare the extern "C" bindings for the extism PDK so Wasm can call it
#[extism_pdk::host_fn]
extern "ExtismHost" {
    pub fn dns_resolve(domain: String) -> String;
    pub fn kv_get(key: String) -> String;
    pub fn kv_set(input: String) -> String;
}

pub fn resolve_dns(domain: &str) -> Option<Vec<String>> {
    let res = unsafe { dns_resolve(domain.to_string()) };
    if let Ok(json) = res {
        if let Ok(ips) = serde_json::from_str::<Vec<String>>(&json) {
            return Some(ips);
        }
    }
    None
}

pub fn get_state(key: &str) -> Option<String> {
    let res = unsafe { kv_get(key.to_string()) };
    if let Ok(content) = res {
        if !content.is_empty() {
            return Some(content);
        }
    }
    None
}

pub fn set_state(key: &str, value: &str) -> bool {
    // encode to json
    let json = format!(r#"{{"key":"{}","value":"{}"}}"#, key, value);
    let res = unsafe { kv_set(json) };
    if let Ok(status) = res {
        return status == "ok";
    }
    false
}
