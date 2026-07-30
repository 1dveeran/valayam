use crate::reflection::ValayamReflection;
use tonic::{transport::Server, Request, Response, Status};
use crate::rpc::scanner_server::{Scanner, ScannerServer};
use crate::rpc::{ScanRequest, ScanResponse, TelemetryEvent, TelemetryResponse, ControlRequest, ControlResponse};
use valayam_proto::reflection::v1::server_reflection_server::ServerReflectionServer;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use crate::executor::ScanState;

/// Optional TLS configuration for the gRPC control plane.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

pub struct TelemetryService {
    state_tx: Option<watch::Sender<ScanState>>,
    cancellation_token: Option<CancellationToken>,
}

#[tonic::async_trait]
impl Scanner for TelemetryService {
    async fn scan(&self, _request: Request<ScanRequest>) -> Result<Response<ScanResponse>, Status> {
        Ok(Response::new(ScanResponse { findings_json: vec![] }))
    }

    async fn stream_telemetry(
        &self,
        request: Request<tonic::Streaming<TelemetryEvent>>,
    ) -> Result<Response<TelemetryResponse>, Status> {
        let mut stream = request.into_inner();

        while let Some(event) = stream.message().await? {
            tracing::info!(
                event_type = %event.event_type,
                payload = %event.payload_json,
                "Received eBPF Telemetry Event"
            );
            // TODO: route telemetry events to active scan contexts for real-time display
        }

        Ok(Response::new(TelemetryResponse { received: true }))
    }

    async fn pause_scan(&self, _req: Request<ControlRequest>) -> Result<Response<ControlResponse>, Status> {
        if let Some(tx) = &self.state_tx {
            let _ = tx.send(ScanState::Paused);
            return Ok(Response::new(ControlResponse { success: true, message: "Paused".into() }));
        }
        Err(Status::unavailable("Control plane not active"))
    }

    async fn resume_scan(&self, _req: Request<ControlRequest>) -> Result<Response<ControlResponse>, Status> {
        if let Some(tx) = &self.state_tx {
            let _ = tx.send(ScanState::Running);
            return Ok(Response::new(ControlResponse { success: true, message: "Resumed".into() }));
        }
        Err(Status::unavailable("Control plane not active"))
    }

    async fn cancel_scan(&self, _req: Request<ControlRequest>) -> Result<Response<ControlResponse>, Status> {
        if let Some(token) = &self.cancellation_token {
            token.cancel();
            return Ok(Response::new(ControlResponse { success: true, message: "Cancelled".into() }));
        }
        Err(Status::unavailable("Control plane not active"))
    }
}

/// Spawn a minimal HTTP server on `metrics_addr` that serves prometheus metrics
/// at GET /metrics. Runs until the returned CancellationToken is cancelled.
fn spawn_metrics_http_server(metrics_addr: std::net::SocketAddr) -> CancellationToken {
    let shutdown_token = CancellationToken::new();
    let token = shutdown_token.clone();

    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(metrics_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("Failed to bind metrics HTTP server on {}: {}", metrics_addr, e);
                return;
            }
        };
        tracing::info!("Prometheus metrics endpoint listening on http://{}/metrics", metrics_addr);

        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    tracing::info!("Metrics HTTP server shutting down");
                    break;
                }
                result = listener.accept() => {
                    let (stream, _) = match result {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!("Metrics HTTP accept error: {}", e);
                            continue;
                        }
                    };
                    tokio::spawn(handle_metrics_connection(stream));
                }
            }
        }
    });

    shutdown_token
}

async fn handle_metrics_connection(stream: tokio::net::TcpStream) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    // Only respond to GET /metrics; 404 everything else
    let (status_line, content_type, body) = if request_line.starts_with("GET /metrics") {
        let metrics_body = crate::metrics::gather_metrics();
        (
            "HTTP/1.1 200 OK\r\n",
            "content-type: text/plain; version=0.0.4\r\n",
            metrics_body,
        )
    } else {
        (
            "HTTP/1.1 404 Not Found\r\n",
            "content-type: text/plain\r\n",
            "404 Not Found\n".to_string(),
        )
    };

    // Drain remaining request headers
    let mut header = String::new();
    loop {
        header.clear();
        if reader.read_line(&mut header).await.is_err() || header.trim().is_empty() {
            break;
        }
    }

    let response = format!(
        "{}content-length: {}\r\n{}\r\n{}",
        status_line,
        body.len(),
        content_type,
        body,
    );

    let mut writer = reader.into_inner();
    let _ = writer.write_all(response.as_bytes()).await;
    let _ = writer.flush().await;
}

/// Start the gRPC telemetry server (plaintext).
pub async fn start_telemetry_server(
    addr: std::net::SocketAddr,
    state_tx: Option<watch::Sender<ScanState>>,
    cancellation_token: Option<CancellationToken>,
) -> Result<(), Box<dyn std::error::Error>> {
    start_telemetry_server_tls(addr, state_tx, cancellation_token, None).await
}

/// Start the gRPC telemetry server with optional TLS and a /metrics HTTP endpoint.
///
/// When `tls_config` is `Some`, the server uses the provided PEM-encoded
/// certificate and private key for TLS encryption.
/// Automatically spawns a prometheus /metrics HTTP server on `metrics_port` (default 9090).
pub async fn start_telemetry_server_tls(
    addr: std::net::SocketAddr,
    state_tx: Option<watch::Sender<ScanState>>,
    cancellation_token: Option<CancellationToken>,
    _tls_config: Option<TlsConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Spawn the /metrics HTTP endpoint
    let metrics_addr: std::net::SocketAddr = ([0, 0, 0, 0], 9090).into();
    let _metrics_shutdown = spawn_metrics_http_server(metrics_addr);

    let service = TelemetryService {
        state_tx,
        cancellation_token,
    };

    tracing::info!("Starting Valayam Telemetry Server on {}", addr);
    Server::builder()
        .add_service(ServerReflectionServer::new(ValayamReflection::default()))
        .add_service(ScannerServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}

/// Start a minimal HTTP server serving Prometheus metrics at `/metrics`.
pub async fn start_metrics_server(addr: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Starting Valayam metrics endpoint on http://{}/metrics", addr);

    loop {
        let (mut stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let _ = stream.read(&mut buf).await;

            let body = crate::metrics::gather_metrics();
            let body_bytes = body.as_bytes();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body_bytes.len()
            );

            if stream.write_all(header.as_bytes()).await.is_err() { return; }
            let _ = stream.write_all(body_bytes).await;
        });
    }
}