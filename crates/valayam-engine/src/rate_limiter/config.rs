#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    pub base_rps: u32,
    pub burst_size: Option<u32>,
    pub backoff_factor: f32,
    pub max_backoff: u32,
    pub respect_retry_after: bool,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            base_rps: 10,
            burst_size: None,
            backoff_factor: 1.5,
            max_backoff: 60,
            respect_retry_after: true,
        }
    }
}
