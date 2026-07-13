use futures::future::join_all;
use std::collections::HashSet;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use super::tcp::PortResult; // Reuse PortResult from tcp.rs

/// Parses a list of port strings, expanding ranges into individual port numbers.
/// E.g., ["53", "161", "8000-8005"] -> {53, 161, 8000, 8001, ..., 8005}
fn parse_ports(ports: &[String]) -> Result<HashSet<u16>, String> {
    let mut parsed_ports = HashSet::new();
    for port_str in ports {
        if let Some((start, end)) = port_str.split_once('-') {
            let start_port: u16 = start.trim().parse().map_err(|_| format!("Invalid port range start: {}", start))?;
            let end_port: u16 = end.trim().parse().map_err(|_| format!("Invalid port range end: {}", end))?;
            if start_port > end_port {
                return Err(format!("Invalid port range: start > end ({} > {})", start_port, end_port));
            }
            for port in start_port..=end_port {
                parsed_ports.insert(port);
            }
        } else {
            let port: u16 = port_str.trim().parse().map_err(|_| format!("Invalid port: {}", port_str))?;
            parsed_ports.insert(port);
        }
    }
    Ok(parsed_ports)
}

/// Performs a concurrent UDP probe on a list of ports for a given host.
/// UDP is stateless, so we send an empty payload (or a specific probe) and wait for a response.
pub async fn scan_ports(
    host: &str,
    ports: &[String],
    banner_timeout_ms: Option<u64>,
) -> Vec<PortResult> {
    let Ok(parsed_ports) = parse_ports(ports) else {
        eprintln!("[!] Invalid UDP port format provided.");
        return Vec::new();
    };

    let scan_futures = parsed_ports.into_iter().map(|port| {
        let host = host.to_string();
        let banner_ms = banner_timeout_ms.unwrap_or(2000); // default to 2 seconds wait for UDP
        tokio::spawn(async move {
            let address = format!("{}:{}", host, port);
            
            // Bind to a local ephemeral port
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => return None,
            };

            if socket.connect(&address).await.is_err() {
                return None;
            }

            // Send a generic probe (empty or generic payload depending on expected service)
            // For general UDP probing, we send an empty packet.
            if socket.send(b"").await.is_err() {
                return None;
            }

            let mut buf = vec![0u8; 1024];
            let read_timeout = Duration::from_millis(banner_ms);
            
            match timeout(read_timeout, socket.recv(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = Some(String::from_utf8_lossy(&buf[..n]).to_string());
                    Some(PortResult { port, banner })
                }
                // If we get an error or timeout, we assume port is closed/filtered for UDP
                _ => None,
            }
        })
    });

    let results = join_all(scan_futures).await;

    results
        .into_iter()
        .filter_map(|res| res.unwrap_or(None))
        .collect()
}
