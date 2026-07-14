use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;

/// Embedded HTTP/DNS Server for Out-of-Band interactions.
pub struct OobServer {
    pub bind_address: String,
    pub hits: Arc<Mutex<HashMap<String, Vec<OobInteraction>>>>,
}

#[derive(Debug, Clone)]
pub struct OobInteraction {
    pub protocol: String, // "dns" or "http"
    pub source_ip: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub raw_request: String,
}

impl OobServer {
    pub fn new(bind_address: &str) -> Self {
        Self {
            bind_address: bind_address.to_string(),
            hits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Starts the HTTP and DNS listeners in the background.
    pub async fn start(&self) -> Result<(), String> {
        // TODO: Implement actual hyper/hickory-dns server binding
        tracing::info!("OOB Server started on {}", self.bind_address);
        Ok(())
    }

    /// Checks if a correlation ID received any hits.
    pub async fn check_hits(&self, correlation_id: &str) -> Option<Vec<OobInteraction>> {
        let lock = self.hits.lock().await;
        lock.get(correlation_id).cloned()
    }
}
