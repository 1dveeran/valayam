use tonic::{transport::Server, Request, Response, Status};
use crate::rpc::scanner_server::{Scanner, ScannerServer};
use crate::rpc::{ScanRequest, ScanResponse, TelemetryEvent, TelemetryResponse, ControlRequest, ControlResponse};
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
            // Here we would route it to the active scan contexts to verify execution, etc.
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
        .add_service(ScannerServer::new(service))
        .serve(addr)
        .await?;
        
    Ok(())
}
