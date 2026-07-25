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
            let now = Instant::now().elapsed().as_millis() as u64; // Fallback time tracking
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

/// Adaptive Rate Limiter adjusts its delay based on server responses.
pub struct AdaptiveRateLimiter {
    current_delay_ms: AtomicU64,
    min_delay_ms: u64,
    max_delay_ms: u64,
}

impl AdaptiveRateLimiter {
    pub fn new(initial_delay_ms: u64, min_delay_ms: u64, max_delay_ms: u64) -> Self {
        Self {
            current_delay_ms: AtomicU64::new(initial_delay_ms),
            min_delay_ms,
            max_delay_ms,
        }
    }

    pub async fn wait(&self) {
        let delay = self.current_delay_ms.load(Ordering::Relaxed);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
    }

    pub fn handle_too_many_requests(&self) {
        let mut delay = self.current_delay_ms.load(Ordering::Relaxed);
        delay = (delay * 2).clamp(self.min_delay_ms.max(100), self.max_delay_ms);
        self.current_delay_ms.store(delay, Ordering::Relaxed);
    }

    pub fn handle_success(&self) {
        let mut delay = self.current_delay_ms.load(Ordering::Relaxed);
        if delay > self.min_delay_ms {
            delay = (delay - (delay / 10)).max(self.min_delay_ms);
            self.current_delay_ms.store(delay, Ordering::Relaxed);
        }
    }
}
