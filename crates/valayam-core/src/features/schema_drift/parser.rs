use serde::{Deserialize, Serialize};

fn default_crawl_depth() -> u32 {
    2
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SchemaDriftTemplate {
    pub target: String,
    pub openapi_spec: String,
    /// Crawl depth for discovering endpoints. Defaults to 2.
    #[serde(default = "default_crawl_depth")]
    pub crawl_depth: u32,
}
