// TODO: Optimize RateLimiter for Enterprise Batch processing.
// - Benchmark `governor` under 10k+ concurrent async tasks.
// - Implement dynamic backoff integration for 429 Too Many Requests.
use std::num::NonZeroU32;
use std::sync::Arc;
use governor::{Quota, RateLimiter as GovLimiter, clock, state, middleware};

type GovernorLimiter = GovLimiter<
    state::NotKeyed,
    state::InMemoryState,
    clock::DefaultClock,
    middleware::NoOpMiddleware<clock::QuantaInstant>,
>;

/// Thread-safe, global request rate limiter using the Token Bucket algorithm.
///
/// Shared across all async tasks via `Arc`. Each call to `acquire()` awaits
/// until a token is available, ensuring the scanner never exceeds the
/// configured requests-per-second limit.
#[derive(Clone)]
pub struct RateLimiter {
    limiter: Arc<GovernorLimiter>,
}

impl RateLimiter {
    /// Creates a new rate limiter allowing `rps` requests per second.
    ///
    /// # Panics
    /// Panics if `rps` is 0.
    pub fn new(rps: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(rps).expect("RPS must be > 0"));
        let limiter = GovLimiter::direct(quota);
        Self {
            limiter: Arc::new(limiter),
        }
    }

    /// Awaits until a request token is available. This is a non-blocking
    /// async operation that integrates with the tokio runtime.
    pub async fn acquire(&self) {
        self.limiter.until_ready().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_does_not_block_under_limit() {
        let limiter = RateLimiter::new(100);
        // Should complete instantly — we're well under 100 RPS
        limiter.acquire().await;
        limiter.acquire().await;
        limiter.acquire().await;
    }

    #[test]
    #[should_panic(expected = "RPS must be > 0")]
    fn test_rate_limiter_zero_rps_panics() {
        let _ = RateLimiter::new(0);
    }
}
