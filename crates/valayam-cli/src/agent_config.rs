use serde::{Deserialize, Serialize};

/// Agent configuration — defines how this worker connects to the platform.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Platform base URL, e.g. "https://api.valayam.io"
    pub platform_url: String,

    /// Unique worker identifier, e.g. "node-alpha-us-east"
    pub worker_id: String,

    /// Seconds between job poll attempts (default 5)
    pub poll_interval_secs: u64,

    /// Seconds between heartbeat reports (default 15)
    pub heartbeat_interval_secs: u64,

    /// Worker capabilities advertised to the platform
    pub capabilities: Vec<String>,

    /// Shared secret for HMAC job token verification
    pub job_secret: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            platform_url: "http://localhost:8000".into(),
            worker_id: uuid::Uuid::new_v4().to_string(),
            poll_interval_secs: 5,
            heartbeat_interval_secs: 15,
            capabilities: vec!["wasm".into(), "grpc".into(), "native".into()],
            job_secret: String::new(),
        }
    }
}

// ── Wire protocol types ─────────────────────────────────────────

/// Job dispatched by the platform for the worker to execute.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AgentJob {
    pub job_id: String,
    pub target_url: String,
    pub templates: Vec<AgentJobTemplate>,
    pub config: AgentJobConfig,
    pub auth: Option<AgentJobAuth>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AgentJobTemplate {
    pub id: String,
    pub yaml: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AgentJobConfig {
    pub concurrency: Option<usize>,
    pub rate_limit: Option<u32>,
    pub timeout_secs: Option<u64>,
    pub crawl: Option<bool>,
    pub crawl_depth: Option<usize>,
    pub random_agent: Option<bool>,
    pub output_format: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AgentJobAuth {
    pub job_token: String,
    pub headers: Option<std::collections::HashMap<String, String>>,
}

/// Result payload posted back to the platform.
#[derive(Debug, Serialize)]
pub struct AgentJobResult {
    pub job_id: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: String,
    pub worker_id: String,
    pub metrics: serde_json::Value,
    pub findings: Vec<serde_json::Value>,
    pub errors: Vec<serde_json::Value>,

    /// HMAC token echoed back from the job dispatch, for platform-side verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_token: Option<String>,
}

/// Heartbeat payload pushed to the platform every N seconds.
#[derive(Debug, Serialize)]
pub struct AgentHeartbeat {
    pub worker_id: String,
    pub version: String,
    pub status: String,
    pub current_job_id: Option<String>,
    pub cpu_usage_pct: f32,
    pub memory_usage_pct: f32,
    pub uptime_secs: u64,
    pub plugins_loaded: u32,
    pub templates_cached: u32,
}

/// Response from `POST /jobs/poll` — either a job or a `no-content` signal.
#[derive(Debug, Deserialize)]
pub struct PollResponse {
    pub job: Option<AgentJob>,
}

/// Poll error response
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct PollError {
    pub error: String,
}