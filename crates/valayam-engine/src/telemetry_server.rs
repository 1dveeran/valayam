use crate::reflection::ValayamReflection;
use tonic::{transport::Server, Request, Response, Status};
use crate::rpc::scanner_server::{Scanner, ScannerServer};
use crate::rpc::{ScanRequest, ScanResponse, TelemetryEvent, TelemetryResponse, ControlRequest, ControlResponse};
use valayam_proto::reflection::v1::server_reflection_server::ServerReflectionServer;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use crate::executor::ScanState;

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
            // TODO: route telemetry to active scan contexts
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

pub async fn start_telemetry_server(
    addr: std::net::SocketAddr,
    state_tx: Option<watch::Sender<ScanState>>,
    cancellation_token: Option<CancellationToken>,
) -> Result<(), Box<dyn std::error::Error>> {
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