// TODO: Expand ScannerError enum.
// - Map all Phase 1-30 slice errors to this central enum.
// - Ensure error variants serialize cleanly for SIEM ingestion.
use thiserror::Error;
use std::io;
use std::net::AddrParseError;

/// Unified error enum for all scanner operations.
/// Designed for consistent error handling and SIEM-friendly serialization.
#[derive(Error, Debug)]
pub enum ScannerError {
    // Template/I/O Errors
    #[error("Failed to read template file: {0}")]
    TemplateReadError(io::Error),

    #[error("Failed to parse YAML template: {0}")]
    TemplateParseError(#[from] serde_yaml::Error),

    #[error("Template validation failed: {0}")]
    TemplateValidationError(String),

    // HTTP Client Errors
    #[error("Failed to build HTTP client: {0}")]
    HttpClientError(#[from] reqwest::Error),

    #[error("Invalid HTTP Method defined in template: {0}")]
    InvalidHttpMethod(String),

    // Script Engine Errors
    #[error("Failed to initialize script engine: {0}")]
    ScriptEngineInitError(String),

    #[error("Failed to execute script: {0}")]
    ScriptExecutionError(String),

    // Network Errors
    #[error("Network connection failed: {0}")]
    NetworkError(#[from] tokio::io::Error),

    #[error("DNS resolution failed for {host}: {error}")]
    DnsResolutionError {
        host: String,
        error: String,
    },

    #[error("TCP connection failed to {host}:{port}: {error}")]
    TcpConnectionError {
        host: String,
        port: u16,
        error: String,
    },

    #[error("UDP timeout or failure for {host}:{port}: {error}")]
    UdpError {
        host: String,
        port: u16,
        error: String,
    },

    // TLS Errors
    #[error("TLS handshake failed for {host}:{port}: {error}")]
    TlsHandshakeError {
        host: String,
        port: u16,
        error: String,
    },

    #[error("TLS certificate parsing failed: {0}")]
    TlsCertParseError(String),

    // Input/Validation Errors
    #[error("Invalid target specification: {0}")]
    InvalidTarget(String),

    #[error("Invalid port specification: {0}")]
    InvalidPort(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    // Configuration Errors
    #[error("Invalid configuration: {0}")]
    ConfigurationError(String),

    // Resource Errors
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    // Timeout Errors
    #[error("Operation timed out: {0}")]
    TimeoutError(String),

    // Parsing Errors
    #[error("Failed to parse response data: {0}")]
    ParseError(String),

    // Crypto/TLS Specific Errors
    #[error("Certificate validation failed: {0}")]
    CertificateValidationError(String),

    #[error("Invalid cipher suite: {0}")]
    InvalidCipherSuite(String),

    // Proxy/Network Errors
    #[error("Proxy connection failed: {0}")]
    ProxyError(String),

    // Data Conversion Errors
    #[error("Failed to parse address: {0}")]
    AddressParseError(#[from] AddrParseError),

    // General/Parsing
    #[error("Invalid UTF-8 data: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    // Registry/Plugin Errors
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),

    #[error("Plugin initialization failed: {0}")]
    PluginInitializationError(String),

    #[error("Plugin execution failed: {0}")]
    PluginExecutionError(String),

    // Capture the original error for debugging while maintaining type safety
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

// Implement serialization traits for SIEM/logging compatibility
impl serde::Serialize for ScannerError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        // Create a structured representation for better log analysis
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ScannerError", 3)?;
        state.serialize_field("error_type", &self.to_string())?;
        state.serialize_field("message", &self.to_string())?;
        state.serialize_field("is_retryable", &self.is_retryable())?;
        state.end()
    }
}

impl ScannerError {
    /// Determine if an error is retryable (useful for resilient scanning)
    pub fn is_retryable(&self) -> bool {
        match self {
            ScannerError::NetworkError(_) |
            ScannerError::TimeoutError(_) |
            ScannerError::RateLimitExceeded |
            ScannerError::TlsHandshakeError { .. } |
            ScannerError::DnsResolutionError { .. } |
            ScannerError::TcpConnectionError { .. } |
            ScannerError::UdpError { .. } |
            ScannerError::ProxyError(_) => true,
            _ => false,
        }
    }

    /// Get a standardized error code for categorization
    pub fn error_code(&self) -> &'static str {
        match self {
            ScannerError::TemplateReadError(_) => "TEMPLATE_READ_ERROR",
            ScannerError::TemplateParseError(_) => "TEMPLATE_PARSE_ERROR",
            ScannerError::TemplateValidationError(_) => "TEMPLATE_VALIDATION_ERROR",
            ScannerError::HttpClientError(_) => "HTTP_CLIENT_ERROR",
            ScannerError::InvalidHttpMethod(_) => "INVALID_HTTP_METHOD",
            ScannerError::ScriptEngineInitError(_) => "SCRIPT_INIT_ERROR",
            ScannerError::ScriptExecutionError(_) => "SCRIPT_EXECUTION_ERROR",
            ScannerError::NetworkError(_) => "NETWORK_ERROR",
            ScannerError::DnsResolutionError { .. } => "DNS_RESOLUTION_ERROR",
            ScannerError::TcpConnectionError { .. } => "TCP_CONNECTION_ERROR",
            ScannerError::UdpError { .. } => "UDP_ERROR",
            ScannerError::TlsHandshakeError { .. } => "TLS_HANDSHAKE_ERROR",
            ScannerError::TlsCertParseError(_) => "TLS_CERT_PARSE_ERROR",
            ScannerError::InvalidTarget(_) => "INVALID_TARGET",
            ScannerError::InvalidPort(_) => "INVALID_PORT",
            ScannerError::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            ScannerError::ConfigurationError(_) => "CONFIGURATION_ERROR",
            ScannerError::ResourceExhausted(_) => "RESOURCE_EXHAUSTED",
            ScannerError::TimeoutError(_) => "TIMEOUT_ERROR",
            ScannerError::ParseError(_) => "PARSE_ERROR",
            ScannerError::CertificateValidationError(_) => "CERTIFICATE_VALIDATION_ERROR",
            ScannerError::InvalidCipherSuite(_) => "INVALID_CIPHER_SUITE",
            ScannerError::ProxyError(_) => "PROXY_ERROR",
            ScannerError::AddressParseError(_) => "ADDRESS_PARSE_ERROR",
            ScannerError::Utf8Error(_) => "UTF8_ERROR",
            ScannerError::PluginNotFound(_) => "PLUGIN_NOT_FOUND",
            ScannerError::PluginInitializationError(_) => "PLUGIN_INITIALIZATION_ERROR",
            ScannerError::PluginExecutionError(_) => "PLUGIN_EXECUTION_ERROR",
            ScannerError::Other(_) => "OTHER_ERROR",
        }
    }
}