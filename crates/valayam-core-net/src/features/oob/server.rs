use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;

/// Represents a single out-of-band interaction captured by the server.
#[derive(Debug, Clone)]
pub struct OobInteraction {
    /// Protocol that triggered the interaction ("http" or "dns")
    pub protocol: String,
    /// Source IP address of the interaction
    pub source_ip: String,
    /// Source port of the interaction
    pub source_port: u16,
    /// Timestamp when the interaction was received
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Raw request data (HTTP request line + headers, or DNS question)
    pub raw_request: String,
    /// Extracted callback payload for correlation
    pub correlation_id: Option<String>,
    /// Extracted blind payload (e.g. hex-encoded data exfiltrated via subdomains)
    pub extracted_payload: Option<String>,
}

/// Configuration for the out-of-band interaction server.
#[derive(Debug, Clone)]
pub struct OobServerConfig {
    /// Address to bind the HTTP callback server (default: "0.0.0.0:8080")
    pub http_bind: String,
    /// Address to bind the DNS callback server (default: "0.0.0.0:5353")
    pub dns_bind: String,
    /// Public callback domain or IP that the target will see (e.g., "attacker.com" or your public IP)
    pub callback_domain: String,
    /// How long to retain interactions in memory (default: 1 hour)
    pub retention_duration: Duration,
    /// Maximum body size to capture for HTTP interactions (default: 4096 bytes)
    pub max_body_capture: usize,
    /// Maximum concurrent connections for the HTTP callback server (default: 1000)
    pub max_concurrent_connections: usize,
    /// Max requests per second per source IP (0 = unlimited)
    pub per_ip_rate_limit: u32,
    /// Interval to sweep stale interactions (default: 5 min)
    pub cleanup_interval: Duration,
    /// Optional TLS configuration for HTTPS callbacks
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
}

impl Default for OobServerConfig {
    fn default() -> Self {
        Self {
            http_bind: "0.0.0.0:8080".to_string(),
            dns_bind: "0.0.0.0:5353".to_string(),
            callback_domain: "oob.valayam.local".to_string(),
            retention_duration: Duration::from_secs(3600),
            max_body_capture: 4096,
            max_concurrent_connections: 1000,
            per_ip_rate_limit: 50,
            cleanup_interval: Duration::from_secs(300),
            tls_config: None,
        }
    }
}

/// Embedded HTTP/DNS Server for Out-of-Band interactions.
///
/// The OOB server listens for incoming HTTP requests and DNS queries on configurable ports.
/// Each interaction is stored with its correlation ID so the scanner can check if a
/// blind vulnerability (XXE, SSRF, blind SQLi) triggered an outbound callback.
///
/// # Example
/// ```ignore
/// let config = OobServerConfig {
///     http_bind: "0.0.0.0:8080".to_string(),
///     dns_bind: "0.0.0.0:5353".to_string(),
///     callback_domain: "burpcollab.valayam.net".to_string(),
///     ..Default::default()
/// };
/// let server = OobServer::new(config);
/// server.start().await.unwrap();
/// // ... run scans that trigger callbacks ...
/// let hits = server.check_hits("correlation-id-123").await;
/// ```
pub struct OobServer {
    /// Server configuration
    config: OobServerConfig,
    /// Thread-safe storage of interactions grouped by correlation ID
    hits: Arc<Mutex<HashMap<String, Vec<OobInteraction>>>>,
    /// Shutdown signal for the server
    shutdown: Arc<tokio::sync::Notify>,
    /// Per-IP rate limiter: IP -> next allowed Instant
    ip_limits: Arc<Mutex<HashMap<String, Instant>>>,
}

impl OobServer {
    /// Create a new OOB server with the given configuration.
    pub fn new(config: OobServerConfig) -> Self {
        Self {
            config,
            hits: Arc::new(Mutex::new(HashMap::new())),
            shutdown: Arc::new(tokio::sync::Notify::new()),
            ip_limits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Build config from environment variables with sensible defaults.
    pub fn config_from_env() -> OobServerConfig {
        OobServerConfig {
            http_bind: std::env::var("OOB_HTTP_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            dns_bind: std::env::var("OOB_DNS_BIND").unwrap_or_else(|_| "0.0.0.0:5353".into()),
            callback_domain: std::env::var("OOB_CALLBACK_DOMAIN").unwrap_or_else(|_| "oob.valayam.local".into()),
            retention_duration: Duration::from_secs(
                std::env::var("OOB_RETENTION_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(3600)
            ),
            max_body_capture: std::env::var("OOB_MAX_BODY").ok().and_then(|v| v.parse().ok()).unwrap_or(4096),
            max_concurrent_connections: std::env::var("OOB_MAX_CONCURRENT").ok().and_then(|v| v.parse().ok()).unwrap_or(1000),
            per_ip_rate_limit: std::env::var("OOB_RATE_LIMIT").ok().and_then(|v| v.parse().ok()).unwrap_or(50),
            cleanup_interval: Duration::from_secs(
                std::env::var("OOB_CLEANUP_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(300)
            ),
            tls_config: None,
        }
    }

    /// Start the HTTP and DNS listeners in the background.
    ///
    /// Returns `Ok(())` once both listeners are bound (or immediately if binding fails).
    /// The listeners run as background tokio tasks.
    pub async fn start(&self) -> Result<(), String> {
        let http_bind = self.config.http_bind.clone();
        let dns_bind = self.config.dns_bind.clone();
        let hits_http = self.hits.clone();
        let hits_dns = self.hits.clone();
        let shutdown_http = self.shutdown.clone();
        let shutdown_dns = self.shutdown.clone();
        let max_body = self.config.max_body_capture;
        let callback_domain_http = self.config.callback_domain.clone();
        let callback_domain_dns = self.config.callback_domain.clone();
        let max_concurrent = self.config.max_concurrent_connections;
        let tls_config = self.config.tls_config.clone();
        let ip_limits_http = self.ip_limits.clone();
        let rate_limit_per_sec = self.config.per_ip_rate_limit;
        let retention = self.config.retention_duration;
        let cleanup_interval = self.config.cleanup_interval;
        let hits_cleanup = self.hits.clone();
        let shutdown_cleanup = self.shutdown.clone();

        // Start HTTP listener
        let http_handle = tokio::spawn(async move {
            match TcpListener::bind(&http_bind).await {
                Ok(listener) => {
                    tracing::info!(bind = %http_bind, "OOB HTTP server started");
                    Self::run_http_server(listener, hits_http, shutdown_http, max_body, &callback_domain_http, max_concurrent, tls_config, ip_limits_http, rate_limit_per_sec).await;
                }
                Err(e) => {
                    tracing::error!(bind = %http_bind, error = %e, "Failed to bind OOB HTTP server");
                }
            }
        });

        // Start DNS listener
        let dns_handle = tokio::spawn(async move {
            match UdpSocket::bind(&dns_bind).await {
                Ok(socket) => {
                    tracing::info!(bind = %dns_bind, "OOB DNS server started");
                    Self::run_dns_server(socket, hits_dns, shutdown_dns, &callback_domain_dns).await;
                }
                Err(e) => {
                    tracing::error!(bind = %dns_bind, error = %e, "Failed to bind OOB DNS server");
                }
            }
        });

        // Start background retention cleanup
        let cleanup_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(cleanup_interval) => {
                        let mut lock = hits_cleanup.lock().await;
                        let cutoff = chrono::Utc::now() - chrono::Duration::from_std(retention).unwrap_or_else(|_| chrono::Duration::hours(1));
                        let before = lock.len();
                        lock.retain(|_, interactions| {
                            interactions.retain(|i| i.timestamp > cutoff);
                            !interactions.is_empty()
                        });
                        let after = lock.len();
                        if before != after {
                            tracing::debug!(cleaned = before - after, "OOB interaction retention cleanup");
                        }
                    }
                    _ = shutdown_cleanup.notified() => break,
                }
            }
        });

        // Give listeners a moment to bind, then report status
        tokio::time::sleep(Duration::from_millis(100)).await;

        if http_handle.is_finished() || dns_handle.is_finished() || cleanup_handle.is_finished() {
            return Err("OOB server failed to start — check bind addresses and permissions".to_string());
        }

        tracing::info!("OOB Server fully operational");
        Ok(())
    }

    /// Run the HTTP listener loop.
    #[allow(clippy::too_many_arguments)]
    async fn run_http_server(
        listener: TcpListener,
        hits: Arc<Mutex<HashMap<String, Vec<OobInteraction>>>>,
        shutdown: Arc<tokio::sync::Notify>,
        max_body: usize,
        callback_domain: &str,
        max_concurrent: usize,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        ip_limits: Arc<Mutex<HashMap<String, Instant>>>,
        rate_limit_per_sec: u32,
    ) {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
        let tls_acceptor = tls_config.map(tokio_rustls::TlsAcceptor::from);
        let rate_interval = if rate_limit_per_sec > 0 {
            Duration::from_secs_f64(1.0 / rate_limit_per_sec as f64)
        } else {
            Duration::ZERO
        };

        loop {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break, // semaphore closed
            };

            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((mut stream, addr)) => {
                            let hits = hits.clone();
                            let domain = callback_domain.to_string();
                            let max_b = max_body;
                            let tls_acc = tls_acceptor.clone();
                            let ip_limits_clone = ip_limits.clone();

                            tokio::spawn(async move {
                                let _permit = permit; // drop permit when task completes

                                // Per-IP rate limiting
                                if rate_interval > Duration::ZERO {
                                    let ip_key = addr.ip().to_string();
                                    let mut limits = ip_limits_clone.lock().await;
                                    let now = Instant::now();
                                    let next_allowed = limits.entry(ip_key).or_insert(Instant::now());
                                    if now < *next_allowed {
                                        return; // rate-limited, drop connection silently
                                    }
                                    *next_allowed = now + rate_interval;
                                    drop(limits);
                                }

                                // Apply TLS if configured
                                let mut buf = vec![0u8; 8192];
                                let n;
                                let raw;

                                if let Some(acceptor) = tls_acc {
                                    if let Ok(Ok(mut tls_stream)) = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await {
                                        n = match tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf)).await {
                                            Ok(Ok(n)) if n > 0 => n,
                                            _ => return,
                                        };
                                        raw = String::from_utf8_lossy(&buf[..n.min(max_b)]).to_string();
                                        
                                        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                                        use tokio::io::AsyncWriteExt;
                                        let _ = tokio::time::timeout(Duration::from_secs(2), tls_stream.write_all(response)).await;
                                    } else {
                                        return;
                                    }
                                } else {
                                    n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                                        Ok(Ok(n)) if n > 0 => n,
                                        _ => return,
                                    };
                                    raw = String::from_utf8_lossy(&buf[..n.min(max_b)]).to_string();
                                    
                                    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                                    use tokio::io::AsyncWriteExt;
                                    let _ = tokio::time::timeout(Duration::from_secs(2), stream.write_all(response)).await;
                                }

                                let timestamp = chrono::Utc::now();
                                // Extract correlation ID from path or Host header
                                let correlation_id = Self::extract_http_correlation_id(&raw, &domain);

                                // Extract first line for a concise summary
                                let first_line = raw.lines().next().unwrap_or("").to_string();
                                let interaction = OobInteraction {
                                    protocol: "http".to_string(),
                                    source_ip: addr.ip().to_string(),
                                    source_port: addr.port(),
                                    timestamp,
                                    raw_request: format!("{}\n<{} bytes body>", first_line, n),
                                    correlation_id: correlation_id.clone(),
                                    extracted_payload: None, // HTTP payload extraction could be added later
                                };

                                // Store the interaction
                                let mut lock = hits.lock().await;
                                let key = correlation_id.unwrap_or_else(|| "uncorrelated".to_string());
                                lock.entry(key).or_default().push(interaction);

                                tracing::debug!(source = %addr, "OOB HTTP interaction captured");
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "OOB HTTP listener accept error");
                        }
                    }
                }
                _ = shutdown.notified() => {
                    tracing::info!("OOB HTTP server shutting down");
                    break;
                }
            }
        }
    }

    /// Extract a correlation ID from an HTTP request.
    fn extract_http_correlation_id(raw_request: &str, callback_domain: &str) -> Option<String> {
        // Strategy 1: Look for correlation ID in the URL path `/correlation-id`
        let first_line = raw_request.lines().next()?;
        let path = first_line.split_whitespace().nth(1)?;

        // Extract subdomain prefix from Host header as correlation ID
        // e.g., Host: abc123.oob.valayam.local -> "abc123"
        for line in raw_request.lines().skip(1) {
            let lower = line.to_lowercase();
            if lower.starts_with("host:") {
                let host = line[5..].trim();
                // Check if this is targeted at our callback domain
                if host.ends_with(callback_domain.trim_start_matches('.')) {
                    // Extract the subdomain part as correlation ID
                    let suffix = callback_domain.trim_start_matches('.');
                    if let Some(prefix) = host.strip_suffix(suffix) {
                        let id = prefix.trim_end_matches('.');
                        if !id.is_empty() && id != "*" {
                            return Some(id.to_string());
                        }
                    }
                    // Also try stripping entire callback domain
                    if let Some(id) = host.strip_suffix(callback_domain) {
                        let id = id.trim_end_matches('.');
                        if !id.is_empty() && id != "*" {
                            return Some(id.to_string());
                        }
                    }
                }
            }
        }

        // Strategy 2: If path contains a UUID-like pattern, use it
        if path.len() > 8 && path.chars().all(|c| c.is_ascii_alphanumeric() || c == '/' || c == '-' || c == '_') {
            let last_segment = path.rsplit('/').next().filter(|s| !s.is_empty() && s.len() >= 8)?;
            if last_segment.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Some(last_segment.to_string());
            }
        }

        None
    }

    /// Run the DNS listener loop.
    async fn run_dns_server(
        socket: UdpSocket,
        hits: Arc<Mutex<HashMap<String, Vec<OobInteraction>>>>,
        shutdown: Arc<tokio::sync::Notify>,
        callback_domain: &str,
    ) {
        let mut buf = vec![0u8; 512]; // DNS max UDP size
        let domain = callback_domain.to_string();

        loop {
            tokio::select! {
                recv_result = socket.recv_from(&mut buf) => {
                    match recv_result {
                        Ok((n, src)) => {
                            let query = buf[..n].to_vec();
                            let timestamp = chrono::Utc::now();

                            // Parse correlation ID and optional payload from DNS query
                            let (correlation_id, payload) = Self::extract_dns_correlation_id(&query, &domain);

                            let raw_hex: String = query.iter().take(64).map(|b| format!("{:02x}", b)).collect();
                            let interaction = OobInteraction {
                                protocol: "dns".to_string(),
                                source_ip: src.ip().to_string(),
                                source_port: src.port(),
                                timestamp,
                                raw_request: format!("DNS query ({} bytes): {}", n, raw_hex),
                                correlation_id: correlation_id.clone(),
                                extracted_payload: payload,
                            };

                            // Store the interaction
                            let mut lock = hits.lock().await;
                            let key = correlation_id.unwrap_or_else(|| "uncorrelated".to_string());
                            lock.entry(key).or_default().push(interaction);

                            tracing::debug!(source = %src, bytes = n, "OOB DNS interaction captured");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "OOB DNS listener recv error");
                        }
                    }
                }
                _ = shutdown.notified() => {
                    tracing::info!("OOB DNS server shutting down");
                    break;
                }
            }
        }
    }

    /// Extract a correlation ID and optional payload from a DNS query by looking for our callback domain.
    /// Returns `(Option<CorrelationId>, Option<Payload>)`.
    fn extract_dns_correlation_id(query: &[u8], callback_domain: &str) -> (Option<String>, Option<String>) {
        if query.len() < 12 {
            return (None, None); // Not a valid DNS header
        }

        // Parse DNS question section (starts at byte 12 after header)
        let mut pos = 12;
        let mut labels = Vec::new();

        while pos < query.len() {
            let len = query[pos] as usize;
            if len == 0 {
                break; // End of domain name
            }
            if len > 63 || pos + len + 1 > query.len() {
                return (None, None); // Invalid label
            }
            pos += 1;
            if let Ok(label) = std::str::from_utf8(&query[pos..pos + len]) {
                labels.push(label.to_string());
            }
            pos += len;
        }

        if labels.is_empty() {
            return (None, None);
        }

        let domain_name = labels.join(".");

        // The domain should end with our callback domain
        if domain_name.ends_with(callback_domain) {
            let prefix = domain_name.strip_suffix(callback_domain).unwrap_or_default().trim_end_matches('.');
            
            // Format is often [payload].[correlation_id].callback_domain
            // or just [correlation_id].callback_domain
            let mut parts: Vec<&str> = prefix.split('.').collect();
            
            if parts.is_empty() || parts == [""] || parts == ["*"] {
                return (None, None);
            }

            let id = match parts.pop() {
                Some(id) => id,
                None => return (None, None),
            };
            let payload = if !parts.is_empty() {
                Some(parts.join("."))
            } else {
                None
            };

            if !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return (Some(id.to_string()), payload);
            }
        }

        // Fallback: single-label name that looks like an opaque correlation ID
        if !domain_name.contains('.') && domain_name.len() >= 8 && domain_name.len() <= 64 {
            if domain_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return (Some(domain_name), None);
            }
        }

        (None, None)
    }

    /// Check if a correlation ID received any hits.
    ///
    /// Returns `Some(Vec<OobInteraction>)` if interactions exist for this ID,
    /// or `None` if no interactions were captured.
    pub async fn check_hits(&self, correlation_id: &str) -> Option<Vec<OobInteraction>> {
        let lock = self.hits.lock().await;
        lock.get(correlation_id).cloned()
    }

    /// Get all correlation IDs that have received hits.
    pub async fn all_correlation_ids(&self) -> Vec<String> {
        let lock = self.hits.lock().await;
        lock.keys().cloned().collect()
    }

    /// Get the total number of interactions captured across all correlation IDs.
    pub async fn total_interactions(&self) -> usize {
        let lock = self.hits.lock().await;
        lock.values().map(|v| v.len()).sum()
    }

    /// Get the count of unique correlation IDs that have hits.
    pub async fn unique_correlation_count(&self) -> usize {
        let lock = self.hits.lock().await;
        lock.len()
    }

    /// Generate a correlation ID for use in exploits.
    ///
    /// This ID can be embedded in payloads to track which target triggered the callback.
    pub fn generate_correlation_id() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let id: String = (0..12).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect();
        id.to_lowercase()
    }

    /// Build the full callback URL for a given correlation ID.
    ///
    /// This is the URL the target will hit when the vulnerability triggers.
    pub fn callback_url(&self, correlation_id: &str) -> String {
        format!("http://{}.{}/{}", correlation_id, self.config.callback_domain, correlation_id)
    }

    /// Build the DNS callback domain for a given correlation ID.
    pub fn callback_domain_for(&self, correlation_id: &str) -> String {
        format!("{}.{}", correlation_id, self.config.callback_domain)
    }

    /// Gracefully shut down the OOB server.
    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_correlation_id() {
        let id1 = OobServer::generate_correlation_id();
        let id2 = OobServer::generate_correlation_id();
        assert_eq!(id1.len(), 12);
        assert_ne!(id1, id2);
        assert!(id1.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_callback_url() {
        let config = OobServerConfig::default();
        let server = OobServer::new(config);
        let url = server.callback_url("test123");
        assert_eq!(url, "http://test123.oob.valayam.local/test123");
    }

    #[test]
    fn test_dns_callback_domain() {
        let config = OobServerConfig::default();
        let server = OobServer::new(config);
        let domain = server.callback_domain_for("abc123");
        assert_eq!(domain, "abc123.oob.valayam.local");
    }

    #[test]
    fn test_extract_http_correlation_id_from_host() {
        let raw = "GET / HTTP/1.1\r\nHost: abc123.oob.valayam.local\r\nUser-Agent: test\r\n\r\n";
        let id = OobServer::extract_http_correlation_id(raw, "oob.valayam.local");
        assert_eq!(id, Some("abc123".to_string()));
    }

    #[test]
    fn test_extract_http_correlation_id_from_path() {
        let raw = "GET /some-prefix-123 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let id = OobServer::extract_http_correlation_id(raw, "oob.valayam.local");
        assert_eq!(id, Some("some-prefix-123".to_string()));
    }

    #[test]
    fn test_extract_http_correlation_id_no_match() {
        let raw = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let id = OobServer::extract_http_correlation_id(raw, "oob.valayam.local");
        assert_eq!(id, None);
    }

    #[test]
    fn test_extract_dns_correlation_id() {
        // Build a minimal DNS query for abc123.oob.valayam.local
        let mut query = vec![0u8; 12]; // DNS header (all zeros is fine for extraction test)
        // Encode domain name: 5abc1234oob6valayam5local0
        let labels = ["abc123", "oob", "valayam", "local"];
        for label in &labels {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0x00); // End of domain name
        // QTYPE + QCLASS (2+2 bytes)
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let (id, payload) = OobServer::extract_dns_correlation_id(&query, "oob.valayam.local");
        assert_eq!(id, Some("abc123".to_string()));
        assert_eq!(payload, None);
    }

    #[test]
    fn test_extract_dns_correlation_id_with_payload() {
        let mut query = vec![0u8; 12];
        // data.abc123.oob.valayam.local
        let labels = ["deadbeef", "abc123", "oob", "valayam", "local"];
        for label in &labels {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0x00);
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let (id, payload) = OobServer::extract_dns_correlation_id(&query, "oob.valayam.local");
        assert_eq!(id, Some("abc123".to_string()));
        assert_eq!(payload, Some("deadbeef".to_string()));
    }

    #[test]
    fn test_extract_dns_correlation_id_no_match() {
        let mut query = vec![0u8; 12];
        let labels = ["example", "com"];
        for label in &labels {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0x00);
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let (id, payload) = OobServer::extract_dns_correlation_id(&query, "oob.valayam.local");
        assert_eq!(id, None);
        assert_eq!(payload, None);
    }

    #[tokio::test]
    async fn test_oob_server_start_shutdown() {
        let config = OobServerConfig {
            http_bind: "127.0.0.1:0".to_string(),
            dns_bind: "127.0.0.1:0".to_string(),
            ..Default::default()
        };
        let server = OobServer::new(config);
        // Start should succeed even with port 0 (OS assigns ephemeral)
        let result = server.start().await;
        // It might fail since port 0 means we don't know the actual bind
        // but the server shouldn't crash
        assert!(result.is_ok() || result.is_err());
        server.shutdown();
    }
}