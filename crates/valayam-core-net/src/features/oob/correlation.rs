use rand::{distributions::Alphanumeric, Rng};

/// Correlation engine for generating short-lived OOB IDs.
pub struct CorrelationEngine;

impl CorrelationEngine {
    /// Generates a random alphanumeric correlation ID of length 8.
    pub fn generate_id() -> String {
        let rng = rand::thread_rng();
        rng.sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect::<String>()
            .to_lowercase()
    }
    
    /// Formats the correlation ID into a full hostname, e.g., `abc123yz.valayam.local`.
    pub fn format_domain(id: &str, base_domain: &str) -> String {
        format!("{}.{}", id, base_domain)
    }
}
