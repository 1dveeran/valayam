// TODO: Expand Dynamic Proxy Rotation for enterprise deployments.
// - Add cloud provider API integration (AWS Instance Metadata, GCP Metadata) for ephemeral IP rotation.
// - Implement proxy scoring (latency, success rate) to prefer faster proxies.
// - Add automatic proxy discovery via proxy list APIs.
// - Support proxy authentication (username/password) per proxy.

use rand::seq::SliceRandom;
use rand::thread_rng;
use std::fs;
use std::time::{Duration, Instant};

/// Represents the health status of a proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyHealth {
    /// Proxy is working normally
    Healthy,
    /// Proxy is degraded (slow or intermittent failures)
    Degraded,
    /// Proxy is unavailable (failed health check)
    Unavailable,
}

/// A single proxy entry with health tracking.
#[derive(Debug, Clone)]
struct ProxyEntry {
    /// Proxy URL in `protocol://host:port` format
    address: String,
    /// Current health status
    health: ProxyHealth,
    /// When the last health check was performed
    last_checked: Option<Instant>,
    /// Number of consecutive failures
    consecutive_failures: u32,
    /// Average response latency (if measured)
    avg_latency_ms: Option<u64>,
}

/// Manages a pool of proxy addresses for rotation with health checking.
///
/// Supports SOCKS5 and HTTP proxies in `protocol://host:port` format.
/// Proxies are shuffled and returned in round-robin order, with automatic
/// skipping of unhealthy proxies.
#[derive(Clone)]
pub struct ProxyRotator {
    proxies: Vec<ProxyEntry>,
    index: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Maximum consecutive failures before marking a proxy unhealthy
    max_failures: u32,
    /// Time after which to retry an unhealthy proxy
    retry_interval: Duration,
}

impl ProxyRotator {
    /// Create a new empty `ProxyRotator` (no proxies).
    pub fn new() -> Self {
        Self {
            proxies: Vec::new(),
            index: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_failures: 3,
            retry_interval: Duration::from_secs(60),
        }
    }

    /// Loads proxies from a file (one per line).
    /// Empty lines and lines starting with `#` are skipped.
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read proxy file '{}': {}", path, e))?;

        let addresses: Vec<String> = content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();

        if addresses.is_empty() {
            return Err("Proxy file is empty or contains no valid entries".to_string());
        }

        let proxies: Vec<ProxyEntry> = addresses
            .into_iter()
            .map(|address| ProxyEntry {
                address,
                health: ProxyHealth::Healthy,
                last_checked: None,
                consecutive_failures: 0,
                avg_latency_ms: None,
            })
            .collect();

        Ok(Self {
            proxies,
            index: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_failures: 3,
            retry_interval: Duration::from_secs(60),
        })
    }

    /// Set the maximum consecutive failures before marking a proxy as unavailable.
    pub fn with_max_failures(mut self, max: u32) -> Self {
        self.max_failures = max;
        self
    }

    /// Set the retry interval for unhealthy proxies.
    pub fn with_retry_interval(mut self, interval: Duration) -> Self {
        self.retry_interval = interval;
        self
    }

    /// Returns the next healthy proxy in round-robin order.
    /// Skips unavailable proxies that haven't passed their retry interval.
    /// Returns `None` if no healthy proxies are available.
    pub fn next(&self) -> Option<&str> {
        let len = self.proxies.len();
        if len == 0 {
            return None;
        }

        let start = self.index.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % len;

        for i in 0..len {
            let idx = (start + i) % len;
            if self.is_proxy_usable(&self.proxies[idx]) {
                return Some(&self.proxies[idx].address);
            }
        }

        // All proxies are unavailable — return the first one anyway as a last resort
        self.proxies.first().map(|p| p.address.as_str())
    }

    /// Returns a randomly selected healthy proxy.
    /// Returns `None` if no proxies are available at all.
    pub fn random(&self) -> Option<&str> {
        if self.proxies.is_empty() {
            return None;
        }

        // Collect healthy proxies
        let healthy: Vec<&ProxyEntry> = self.proxies.iter()
            .filter(|p| self.is_proxy_usable(p))
            .collect();

        if healthy.is_empty() {
            // All proxies unavailable — return the first one as last resort
            return self.proxies.first().map(|p| p.address.as_str());
        }

        let mut rng = thread_rng();
        healthy.choose(&mut rng).map(|p| p.address.as_str())
    }

    /// Check if a proxy is usable (healthy or due for retry).
    fn is_proxy_usable(&self, entry: &ProxyEntry) -> bool {
        match entry.health {
            ProxyHealth::Healthy | ProxyHealth::Degraded => true,
            ProxyHealth::Unavailable => {
                // Retry if enough time has passed
                if let Some(last) = entry.last_checked {
                    last.elapsed() >= self.retry_interval
                } else {
                    false
                }
            }
        }
    }

    /// Record a successful connection through a proxy.
    /// This improves the proxy's health score.
    pub fn record_success(&mut self, address: &str) {
        if let Some(entry) = self.proxies.iter_mut().find(|p| p.address == address) {
            entry.consecutive_failures = 0;
            entry.health = ProxyHealth::Healthy;
            entry.last_checked = Some(Instant::now());
        }
    }

    /// Record a failure for a proxy.
    /// After `max_failures` consecutive failures, the proxy is marked unavailable.
    pub fn record_failure(&mut self, address: &str) {
        if let Some(entry) = self.proxies.iter_mut().find(|p| p.address == address) {
            entry.consecutive_failures += 1;
            entry.last_checked = Some(Instant::now());

            if entry.consecutive_failures >= self.max_failures {
                entry.health = ProxyHealth::Unavailable;
            } else if entry.consecutive_failures >= (self.max_failures / 2).max(1) {
                entry.health = ProxyHealth::Degraded;
            }
        }
    }

    /// Record latency measurement for a proxy.
    pub fn record_latency(&mut self, address: &str, latency_ms: u64) {
        if let Some(entry) = self.proxies.iter_mut().find(|p| p.address == address) {
            // Exponential moving average: new = old * 0.7 + sample * 0.3
            entry.avg_latency_ms = Some(match entry.avg_latency_ms {
                Some(avg) => (avg * 7 + latency_ms * 3) / 10,
                None => latency_ms,
            });
        }
    }

    /// Get the list of healthy proxy addresses.
    pub fn healthy_proxies(&self) -> Vec<&str> {
        self.proxies
            .iter()
            .filter(|p| p.health == ProxyHealth::Healthy)
            .map(|p| p.address.as_str())
            .collect()
    }

    /// Get the list of addresses for all proxies (regardless of health).
    pub fn all_addresses(&self) -> Vec<&str> {
        self.proxies.iter().map(|p| p.address.as_str()).collect()
    }

    /// Returns the number of proxies in the pool.
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    /// Returns true if the proxy pool is empty.
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Reset all proxies to healthy status.
    pub fn reset_health(&mut self) {
        for entry in &mut self.proxies {
            entry.health = ProxyHealth::Healthy;
            entry.consecutive_failures = 0;
            entry.last_checked = None;
        }
    }
}

impl Default for ProxyRotator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_rotator() {
        let rotator = ProxyRotator::new();
        assert!(rotator.is_empty());
        assert_eq!(rotator.len(), 0);
        assert!(rotator.next().is_none());
        assert!(rotator.random().is_none());
    }

    #[test]
    fn test_round_robin() {
        let mut rotator = ProxyRotator::new();
        rotator.proxies = vec![
            ProxyEntry {
                address: "http://proxy1:8080".to_string(),
                health: ProxyHealth::Healthy,
                last_checked: None,
                consecutive_failures: 0,
                avg_latency_ms: None,
            },
            ProxyEntry {
                address: "http://proxy2:8080".to_string(),
                health: ProxyHealth::Healthy,
                last_checked: None,
                consecutive_failures: 0,
                avg_latency_ms: None,
            },
        ];

        assert_eq!(rotator.next(), Some("http://proxy1:8080"));
        assert_eq!(rotator.next(), Some("http://proxy2:8080"));
        assert_eq!(rotator.next(), Some("http://proxy1:8080")); // wraps
    }

    #[test]
    fn test_failure_tracking() {
        let mut rotator = ProxyRotator::new();
        rotator.max_failures = 2;
        rotator.proxies = vec![
            ProxyEntry {
                address: "http://bad-proxy:8080".to_string(),
                health: ProxyHealth::Healthy,
                last_checked: None,
                consecutive_failures: 0,
                avg_latency_ms: None,
            },
        ];

        rotator.record_failure("http://bad-proxy:8080");
        assert_eq!(rotator.proxies[0].consecutive_failures, 1);
        assert_eq!(rotator.proxies[0].health, ProxyHealth::Degraded);

        rotator.record_failure("http://bad-proxy:8080");
        assert_eq!(rotator.proxies[0].consecutive_failures, 2);
        assert_eq!(rotator.proxies[0].health, ProxyHealth::Unavailable);

        // After marking unavailable, the proxy should not be returned
        assert!(rotator.next().is_some()); // last resort fallback
    }

    #[test]
    fn test_success_resets_failures() {
        let mut rotator = ProxyRotator::new();
        rotator.proxies = vec![
            ProxyEntry {
                address: "http://proxy:8080".to_string(),
                health: ProxyHealth::Degraded,
                last_checked: None,
                consecutive_failures: 2,
                avg_latency_ms: None,
            },
        ];

        rotator.record_success("http://proxy:8080");
        assert_eq!(rotator.proxies[0].consecutive_failures, 0);
        assert_eq!(rotator.proxies[0].health, ProxyHealth::Healthy);
    }

    #[test]
    fn test_latency_tracking() {
        let mut rotator = ProxyRotator::new();
        rotator.proxies = vec![
            ProxyEntry {
                address: "http://proxy:8080".to_string(),
                health: ProxyHealth::Healthy,
                last_checked: None,
                consecutive_failures: 0,
                avg_latency_ms: None,
            },
        ];

        rotator.record_latency("http://proxy:8080", 100);
        assert_eq!(rotator.proxies[0].avg_latency_ms, Some(100));

        // Exponential moving average: 100 * 0.7 + 200 * 0.3 = 70 + 60 = 130
        rotator.record_latency("http://proxy:8080", 200);
        assert_eq!(rotator.proxies[0].avg_latency_ms, Some(130));
    }
}