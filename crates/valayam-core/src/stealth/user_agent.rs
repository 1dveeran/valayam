// TODO: Upgrade User-Agent Rotation logic.
// - Integrate Machine Learning based generation for statistically normal UAs.
// - Sync UAs with corresponding TLS fingerprints to avoid detection.
use rand::seq::SliceRandom;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::Mutex;

/// User-Agent rotator for browser impersonation
pub struct UserAgentRotator {
    /// Pool of User-Agent strings
    ua_pool: Vec<String>,
    /// Random number generator (wrapped in Mutex for interior mutability via &self)
    rng: Mutex<StdRng>,
}

impl UserAgentRotator {
    /// Create a new UserAgentRotator
    pub fn new() -> Result<Self, crate::core::error::ScannerError> {
        let ua_pool = Self::default_user_agents();

        Ok(Self {
            ua_pool,
            rng: Mutex::new(StdRng::from_entropy()),
        })
    }

    /// Create a new UserAgentRotator with default user agents
    pub fn with_defaults() -> Self {
        Self {
            ua_pool: Self::default_user_agents(),
            rng: Mutex::new(StdRng::from_entropy()),
        }
    }

    fn default_user_agents() -> Vec<String> {
        vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0".to_string(),
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1".to_string(),
        ]
    }

    /// Get the next user agent from rotation
    pub fn get_next_user_agent(&self) -> String {
        self.ua_pool.choose(&mut *self.rng.lock().unwrap()).unwrap_or(&self.ua_pool[0]).to_string()
    }
}