use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use std::time::{Instant, Duration};

/// A simple Circuit Breaker to prevent overwhelming a target that is failing.
pub struct CircuitBreaker {
    failure_count: AtomicUsize,
    success_count: AtomicUsize,
    threshold: usize,
    last_failure_time: AtomicU64,
    reset_timeout_ms: u64,
}

impl CircuitBreaker {
    pub fn new(threshold: usize, reset_timeout_ms: u64) -> Self {
        Self {
            failure_count: AtomicUsize::new(0),
            success_count: AtomicUsize::new(0),
            threshold,
            last_failure_time: AtomicU64::new(0),
            reset_timeout_ms,
        }
    }

    /// Check if the circuit is open (meaning requests should be blocked).
    pub fn is_open(&self) -> bool {
        let fails = self.failure_count.load(Ordering::Relaxed);
        if fails >= self.threshold {
            let last_fail = self.last_failure_time.load(Ordering::Relaxed);
            let _now = Instant::now().elapsed().as_millis() as u64; // Fallback time tracking
            // In a real implementation we'd use a better absolute time reference,
            // but for simplicity we assume time elapsed from process start or use epoch
            let sys_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
            
            if sys_time - last_fail < self.reset_timeout_ms {
                return true;
            }
        }
        false
    }

    pub fn record_success(&self) {
        self.success_count.fetch_add(1, Ordering::Relaxed);
        self.failure_count.store(0, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.failure_count.fetch_add(1, Ordering::Relaxed);
        let sys_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        self.last_failure_time.store(sys_time, Ordering::Relaxed);
    }
}

use tokio::sync::Mutex;
use rand::Rng;

struct TokenBucketState {
    tokens: f64,
    last_refill_time: u64,
}

/// Adaptive Rate Limiter adjusts its delay based on server responses.
/// Implements a token bucket algorithm to support bursting while maintaining an average rate limit.
pub struct AdaptiveRateLimiter {
    current_delay_ms: AtomicU64,
    min_delay_ms: u64,
    max_delay_ms: u64,
    max_burst: u32,
    state: Mutex<TokenBucketState>,
}

impl AdaptiveRateLimiter {
    pub fn new(initial_delay_ms: u64, min_delay_ms: u64, max_delay_ms: u64, max_burst: u32) -> Self {
        let sys_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            current_delay_ms: AtomicU64::new(initial_delay_ms),
            min_delay_ms,
            max_delay_ms,
            max_burst,
            state: Mutex::new(TokenBucketState {
                tokens: max_burst as f64,
                last_refill_time: sys_time,
            }),
        }
    }

    pub async fn wait(&self) {
        let delay_ms = self.current_delay_ms.load(Ordering::Relaxed);
        if delay_ms == 0 {
            return;
        }

        let mut sleep_duration = None;

        {
            let mut state = self.state.lock().await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            
            let time_passed = now.saturating_sub(state.last_refill_time);
            
            // Refill tokens based on time passed
            let tokens_to_add = (time_passed as f64) / (delay_ms as f64);
            state.tokens = (state.tokens + tokens_to_add).min(self.max_burst as f64);
            state.last_refill_time = now;

            if state.tokens >= 1.0 {
                state.tokens -= 1.0;
            } else {
                let wait_ms = ((1.0 - state.tokens) * (delay_ms as f64)) as u64;
                sleep_duration = Some(wait_ms);
                state.tokens = 0.0;
                // Project the next refill time assuming we wait
                state.last_refill_time = now + wait_ms;
            }
        }

        if let Some(wait_ms) = sleep_duration {
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        }
    }

    pub fn handle_too_many_requests(&self) {
        let delay = self.current_delay_ms.load(Ordering::Relaxed);
        let doubled = (delay * 2).clamp(self.min_delay_ms.max(100), self.max_delay_ms);
        
        // Add +/- 20% jitter to prevent thundering herds
        let mut rng = rand::thread_rng();
        let jitter_range = (doubled as f64 * 0.2) as u64;
        
        let new_delay = if jitter_range > 0 {
            let jitter = rng.gen_range(0..=(jitter_range * 2));
            let adjusted = doubled + jitter;
            adjusted.saturating_sub(jitter_range)
        } else {
            doubled
        };
        
        let clamped_delay = new_delay.clamp(self.min_delay_ms, self.max_delay_ms);
        self.current_delay_ms.store(clamped_delay, Ordering::Relaxed);
    }

    pub fn handle_success(&self) {
        let mut delay = self.current_delay_ms.load(Ordering::Relaxed);
        if delay > self.min_delay_ms {
            delay = (delay - (delay / 10)).max(self.min_delay_ms);
            self.current_delay_ms.store(delay, Ordering::Relaxed);
        }
    }
}
