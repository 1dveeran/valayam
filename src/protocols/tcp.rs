use futures::future::join_all;
use std::collections::HashSet;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

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
/// Returns a vector of ports that were found to be open.
pub async fn scan_ports(host: &str, ports: &[String]) -> Vec<u16> {
    let Ok(parsed_ports) = parse_ports(ports) else {
        // In a real app, we'd propagate this error. For now, let's print and return empty.
        eprintln!("[!] Invalid port format provided.");
        return Vec::new();
    };

    let scan_futures = parsed_ports.into_iter().map(|port| {
        let host = host.to_string();
        tokio::spawn(async move {
            let address = format!("{}:{}", host, port);
            let timeout_duration = Duration::from_secs(2);

            match timeout(timeout_duration, TcpStream::connect(&address)).await {
                Ok(Ok(_)) => Some(port),
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
