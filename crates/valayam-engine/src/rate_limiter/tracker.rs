use std::time::Instant;

#[derive(Debug)]
pub struct BackoffTracker {
    pub consecutive_429s: usize,
    pub last_429: Option<Instant>,
    pub backoff_multiplier: u32,
}

impl Default for BackoffTracker {
    fn default() -> Self {
        Self {
            consecutive_429s: 0,
            last_429: None,
            backoff_multiplier: 1,
        }
    }
}
