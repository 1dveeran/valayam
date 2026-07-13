use futures::future::join_all;
use std::collections::HashSet;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Result of a TCP port scan, including optional banner data.
#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub banner: Option<String>,
}

/// Parses a list of port strings, expanding ranges into individual port numbers.
/// E.g., ["80", "443", "8000-8080"] -> {80, 443, 8000, 8001, ..., 8080}
fn parse_ports(ports: &[String]) -> Result<HashSet<u16>, String> {
    let mut parsed_ports = HashSet::new();
    for port_str in ports {
        if let Some((start, end)) = port_str.split_once('-') {
            let start_port: u16 = start
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port range start: {}", start))?;
            let end_port: u16 = end
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port range end: {}", end))?;
            if start_port > end_port {
                return Err(format!(
                    "Invalid port range: start > end ({} > {})",
                    start_port, end_port
                ));
            }
            for port in start_port..=end_port {
                parsed_ports.insert(port);
            }
        } else {
            let port: u16 = port_str
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port: {}", port_str))?;
            parsed_ports.insert(port);
        }
    }
    Ok(parsed_ports)
}

/// Performs a concurrent TCP connect scan on a list of ports for a given host.
/// Returns a vector of `PortResult` for ports that were found to be open.
///
/// If `banner_timeout_ms` is provided, attempts to read the initial service
/// banner from each open port (e.g., SSH version strings, FTP greetings).
pub async fn scan_ports(
    host: &str,
    ports: &[String],
    banner_timeout_ms: Option<u64>,
) -> Vec<PortResult> {
    let Ok(parsed_ports) = parse_ports(ports) else {
        eprintln!("[!] Invalid port format provided.");
        return Vec::new();
    };

    let scan_futures = parsed_ports.into_iter().map(|port| {
        let host = host.to_string();
        let banner_ms = banner_timeout_ms;
        tokio::spawn(async move {
            let address = format!("{}:{}", host, port);
            let connect_timeout = Duration::from_secs(2);

            let mut stream = match timeout(connect_timeout, TcpStream::connect(&address)).await {
                Ok(Ok(s)) => s,
                _ => return None,
            };

            // Port is open — optionally grab the banner
            let mut banner = if let Some(ms) = banner_ms {
                let banner_timeout = Duration::from_millis(ms);
                let mut buf = vec![0u8; 1024];
                match timeout(banner_timeout, stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => {
                        Some(String::from_utf8_lossy(&buf[..n]).to_string())
                    }
                    _ => None,
                }
            } else {
                None
            };

            // Active probe fallback: if no banner was sent automatically, try prompting with an HTTP GET request
            if banner.is_none() && banner_ms.is_some() {
                use tokio::io::AsyncWriteExt;
                if stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.is_ok() {
                    let mut buf = vec![0u8; 1024];
                    let probe_timeout = Duration::from_millis(1000);
                    if let Ok(Ok(n)) = timeout(probe_timeout, stream.read(&mut buf)).await {
                        if n > 0 {
                            banner = Some(String::from_utf8_lossy(&buf[..n]).to_string());
                        }
                    }
                }
            }

            Some(PortResult { port, banner })
        })
    });

    let results = join_all(scan_futures).await;

    results
        .into_iter()
        .filter_map(|res| res.unwrap_or(None))
        .collect()
}
