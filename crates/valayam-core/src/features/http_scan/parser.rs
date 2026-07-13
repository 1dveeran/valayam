use crate::core::matcher::ResponseMatcher;
use crate::features::extractors::parser::Extractor;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Defines a single HTTP request step within a native template.
/// Supports optional request body (for POST/PUT), extractors for dynamic
/// value capture, and matchers for response validation.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpRequestTemplate {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub matchers: Vec<ResponseMatcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}
