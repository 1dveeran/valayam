use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::oneshot;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProxyRequestData {
    pub id: String,
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub struct InterceptedRequest {
    pub request_data: ProxyRequestData,
    pub tx: oneshot::Sender<Option<ProxyRequestData>>,
}

#[derive(Clone)]
pub struct ProxyState {
    pub pending_requests: Arc<DashMap<String, InterceptedRequest>>,
}

impl ProxyState {
    pub fn new() -> Self {
        Self {
            pending_requests: Arc::new(DashMap::new()),
        }
    }
}
