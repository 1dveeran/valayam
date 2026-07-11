use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Failed to read template file: {0}")]
    TemplateReadError(#[from] std::io::Error),

    #[error("Failed to parse YAML template: {0}")]
    TemplateParseError(#[from] serde_yaml::Error),

    #[error("Failed to build HTTP client: {0}")]
    HttpClientError(#[from] reqwest::Error),

    #[error("Invalid HTTP Method defined in template: {0}")]
    InvalidHttpMethod(String),

    #[error("Failed to initialize script engine: {0}")]
    ScriptEngineInitError(String),

    #[error("Failed to execute script: {0}")]
    ScriptExecutionError(String),
}
