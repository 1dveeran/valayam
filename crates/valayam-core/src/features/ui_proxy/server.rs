use axum::{
    routing::{get, post},
    Router, Json,
    response::Html,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Serialize)]
pub struct StatusResponse {
    status: String,
    active_proxies: usize,
}

#[derive(Serialize, Deserialize)]
pub struct ModificationRequest {
    pub request_id: String,
    pub modified_body: Option<String>,
    pub modified_headers: Option<Vec<(String, String)>>,
}

pub struct UiProxyServer;

impl UiProxyServer {
    pub async fn start(port: u16) -> Result<(), String> {
        let app = Router::new()
            .route("/", get(Self::dashboard_handler))
            .route("/api/status", get(Self::status_handler))
            .route("/api/modify", post(Self::modify_handler));

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| e.to_string())?;
        
        // Spawn the server in the background
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("UI Proxy Server error: {}", e);
            }
        });

        Ok(())
    }

    async fn dashboard_handler() -> Html<&'static str> {
        Html(include_str!("index.html"))
    }

    async fn status_handler() -> Json<StatusResponse> {
        Json(StatusResponse {
            status: "running".to_string(),
            active_proxies: 1, // Mock data for now
        })
    }
    
    async fn modify_handler(Json(payload): Json<ModificationRequest>) -> Json<serde_json::Value> {
        // In a real implementation, this would push the modified request to a channel
        // that the MITM proxy is waiting on.
        Json(serde_json::json!({
            "status": "success",
            "message": format!("Request {} modification queued.", payload.request_id)
        }))
    }
}
