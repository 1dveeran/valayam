// TODO: Implement Network primitives for Multi-Protocol Scanning.
// - http.rs: Integrate reqwest with StealthHttpClient for async requests.
// - tcp.rs: Implement TCP Connect scans and banner grabbing timeouts.
// - udp.rs: Implement basic UDP packet probes for service detection.
// - dns.rs: Integrate hickory-resolver for custom DNS (A, CNAME, TXT) querying.
// - tls.rs: Handle TLS handshakes and certificate extraction for auditing.
pub mod dns;
pub mod http;
pub mod tcp;
pub mod tls;
pub mod udp;
