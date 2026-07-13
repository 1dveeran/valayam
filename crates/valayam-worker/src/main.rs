pub mod broker;

use clap::Parser;
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};

use valayam_core::network::http::StealthHttpClient;
use valayam_core::rpc::scanner_server::{Scanner, ScannerServer};
use valayam_core::rpc::{ScanRequest, ScanResponse};
use valayam_core::template::loader::execute_template;
use valayam_core::template::schema::VulnerabilityTemplate;

#[derive(Parser, Debug)]
#[command(name = "valayam-worker", version = "0.1.0", about = "Distributed Worker Daemon")]
struct Args {
    #[arg(
        short = 'b',
        long,
        env = "BROKER_URL",
        help = "Broker connection URL (e.g. redis://127.0.0.1:6379 or amqp://localhost)"
    )]
    broker: Option<String>,

    #[arg(short = 'p', long, default_value = "50051", help = "gRPC Port (only used in gRPC mode)")]
    port: u16,
}

#[derive(Default)]
pub struct ValayamScanner {}

#[tonic::async_trait]
impl Scanner for ValayamScanner {
    async fn scan(
        &self,
        request: Request<ScanRequest>,
    ) -> Result<Response<ScanResponse>, Status> {
        let req = request.into_inner();
        
        tracing::info!("Received gRPC scan request for target: {}", req.target_url);

        let template = VulnerabilityTemplate::load_from_str(&req.template_yaml)
            .map_err(|e| Status::invalid_argument(format!("Failed to parse YAML: {}", e)))?;

        let client = Arc::new(
            StealthHttpClient::new(false, None)
                .map_err(|e| Status::internal(format!("Failed to create HTTP client: {}", e)))?
        );

        let mut findings = Vec::new();
        if let Some(result) = execute_template(&client, &req.target_url, template, None).await {
            let json = serde_json::to_string(&result)
                .map_err(|e| Status::internal(format!("Failed to serialize result: {}", e)))?;
            findings.push(json);
        }

        let reply = ScanResponse {
            findings_json: findings,
        };

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    if let Some(broker_url) = args.broker {
        tracing::info!("Initializing worker in Queue mode connected to: {}", broker_url);
        let mut broker = broker::create_broker(&broker_url).await?;

        loop {
            match broker.pull_task().await {
                Ok(task) => {
                    tracing::info!("Processing queued task for: {}", task.target_url);
                    let template = match VulnerabilityTemplate::load_from_str(&task.template_yaml) {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::error!("Failed to parse task template: {}", e);
                            continue;
                        }
                    };

                    let client = match StealthHttpClient::new(false, None) {
                        Ok(c) => Arc::new(c),
                        Err(e) => {
                            tracing::error!("Failed to initialize HTTP client: {}", e);
                            continue;
                        }
                    };

                    if let Some(result) = execute_template(&client, &task.target_url, template, None).await {
                        if let Err(e) = broker.push_result(&task.task_id, result).await {
                            tracing::error!("Failed to publish results back to broker: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Error pulling task from broker queue: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    } else {
        let addr = format!("0.0.0.0:{}", args.port).parse()?;
        let scanner = ValayamScanner::default();

        tracing::info!("Valayam gRPC worker node listening on {}", addr);

        Server::builder()
            .add_service(ScannerServer::new(scanner))
            .serve(addr)
            .await?;
    }

    Ok(())
}
