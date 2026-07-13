use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// TLS certificate information extracted from a connection.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub issuer: String,
    pub subject: String,
    pub not_before: String,
    pub not_after: String,
    pub is_expired: bool,
    pub is_self_signed: bool,
    pub serial: String,
    pub signature_algorithm: String,
}

/// Connects to a host:port and extracts TLS certificate information.
///
/// Uses a raw TLS handshake via `rustls` to obtain the peer certificate,
/// then parses it with `x509-parser` for detailed field extraction.
pub async fn inspect_certificate(host: &str, port: u16) -> Option<CertInfo> {
    let address = format!("{}:{}", host, port);
    let connect_timeout = Duration::from_secs(5);

    // Connect TCP
    let tcp_stream = match timeout(connect_timeout, TcpStream::connect(&address)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // Install default crypto provider (safe to call multiple times as it returns Err if already installed)
    let _ = rustls::crypto::ring::default_provider().install_default();

    // We intentionally use a permissive verifier
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoCertVerifier))
        .with_no_client_auth();

    let server_name = match rustls::pki_types::ServerName::try_from(host.to_string()) {
        Ok(name) => name,
        Err(_) => return None,
    };

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));

    let tls_stream = match timeout(connect_timeout, connector.connect(server_name, tcp_stream)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // Extract the peer certificate
    let (_, server_conn) = tls_stream.get_ref();
    let certs = server_conn.peer_certificates()?;
    let cert_der = certs.first()?;

    // Parse with x509-parser
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref()).ok()?;

    let issuer = cert.issuer().to_string();
    let subject = cert.subject().to_string();
    let not_before = cert.validity().not_before.to_string();
    let not_after = cert.validity().not_after.to_string();
    let is_expired = !cert.validity().is_valid();
    let is_self_signed = cert.issuer() == cert.subject();
    let serial = cert.raw_serial_as_string();
    let sig_alg = cert.signature_algorithm.algorithm.to_string();

    Some(CertInfo {
        issuer,
        subject,
        not_before,
        not_after,
        is_expired,
        is_self_signed,
        serial,
        signature_algorithm: sig_alg,
    })
}

/// A TLS certificate verifier that accepts any certificate.
/// Used for inspection purposes — we want to see the cert, not validate it.
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
