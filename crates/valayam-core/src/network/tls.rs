// TODO: Deepen TLS Auditing capabilities.
// - Implement raw ClientHello probes to detect legacy SSLv3/TLSv1.0.
// - Add cipher suite ranking and weak cipher detection.
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
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
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
    let tls_version = server_conn.protocol_version().map(|v| format!("{:?}", v));
    let cipher_suite = server_conn.negotiated_cipher_suite().map(|c| format!("{:?}", c.suite()));

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
        tls_version,
        cipher_suite,
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

/// Probes a server for legacy SSL/TLS versions that are not supported by rustls.
/// Returns a list of supported protocol names (e.g., "SSLv3", "TLSv1.0").
pub async fn probe_legacy_tls(host: &str, port: u16) -> Vec<String> {
    let mut supported = Vec::new();
    
    let versions = [
        ("SSLv3", 0x0300),
        ("TLSv1.0", 0x0301),
        ("TLSv1.1", 0x0302),
    ];
    
    for (name, version) in versions {
        if check_tls_version(host, port, version).await {
            supported.push(name.to_string());
        }
    }
    supported
}

async fn check_tls_version(host: &str, port: u16, version: u16) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let address = format!("{}:{}", host, port);
    let Ok(mut stream) = tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(&address)).await.unwrap_or(Err(std::io::Error::from(std::io::ErrorKind::TimedOut))) else {
        return false;
    };
    
    let mut hello = vec![
        0x16, // Handshake
        (version >> 8) as u8, (version & 0xFF) as u8, // Record version
        0x00, 0x2d, // Record length: 45
        0x01, // ClientHello
        0x00, 0x00, 0x29, // Handshake length: 41
        (version >> 8) as u8, (version & 0xFF) as u8, // Client version
    ];
    // 32 bytes random
    hello.extend_from_slice(&[0x0b; 32]);
    hello.extend_from_slice(&[
        0x00, // Session ID length
        0x00, 0x04, // Cipher suites length
        0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x00, 0xff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        0x01, 0x00, // Compression methods length + null compression
    ]);
    
    if stream.write_all(&hello).await.is_err() { return false; }
    
    let mut buf = [0u8; 5];
    if stream.read_exact(&mut buf).await.is_err() { return false; }
    
    if buf[0] == 0x16 {
        let mut hs_buf = [0u8; 4];
        if stream.read_exact(&mut hs_buf).await.is_ok() {
            if hs_buf[0] == 0x02 { // ServerHello
                return true;
            }
        }
    }
    false
}

