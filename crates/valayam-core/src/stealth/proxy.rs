// TODO: Implement Dynamic Proxy Rotation.
// - Add support for health-checking proxies before use.
// - Integrate cloud provider APIs (AWS, GCP) for ephemeral IP rotation.
use rand::seq::SliceRandom;
use std::fs;

/// Manages a pool of proxy addresses for rotation.
/// Supports SOCKS5 and HTTP proxies in `protocol://host:port` format.
#[derive(Clone)]
pub struct ProxyRotator {
    pub proxies: Vec<String>,
    index: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl ProxyRotator {
    /// Loads proxies from a file (one per line).
    /// Empty lines and lines starting with `#` are skipped.
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read proxy file '{}': {}", path, e))?;

        let proxies: Vec<String> = content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();

        if proxies.is_empty() {
            return Err("Proxy file is empty".to_string());
        }

        Ok(Self {
            proxies,
            index: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Returns the next proxy in round-robin order.
    pub fn next(&self) -> &str {
        let idx = self
            .index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.proxies.len();
        &self.proxies[idx]
    }

    /// Returns a randomly selected proxy.
    pub fn random(&self) -> &str {
        let mut rng = rand::thread_rng();
        self.proxies.choose(&mut rng).unwrap_or(&self.proxies[0])
    }

    /// Returns the number of proxies in the pool.
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }
}
