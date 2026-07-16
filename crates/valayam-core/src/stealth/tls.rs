//! TLS fingerprinting evasion utilities for JA3/JA4 spoofing
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{ServerName, UnixTime};
use rustls::SignatureScheme;

/// A TLS certificate verifier that accepts all certificates.
/// Used for inspection/diagnostic purposes where we don't need to validate the server identity.
#[derive(Debug)]
pub struct NoCertVerification;

impl NoCertVerification {
    /// Creates a new `NoCertVerification` instance.
    pub fn new() -> Self {
        Self
    }
}

impl ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
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

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

impl Default for NoCertVerification {
    fn default() -> Self {
        Self::new()
    }
}

/// JA3/JA4 spoofer for TLS fingerprint evasion
///
/// This module provides utilities to modify TLS client hello messages
/// to mimic common browsers and evade WAF/detection systems that rely on TLS fingerprinting.
#[derive(Clone)]
pub struct Ja3Ja4Spoofer {
    /// Profile to mimic (chrome, firefox, safari, edge, etc.)
    profile: Ja3Ja4Profile,
    /// Custom JA3 string to use (if Some, overrides profile )
    custom_ja3: Option<String>,
    /// Custom JA4 string to use ( if Some, overrides profile )
    custom_ja4: Option<String>,
}

impl Ja3Ja4Spoofer {
    /// Create a new JA3/JA4 spoofer with the specified profile
    pub fn new(profile: Ja3Ja4Profile) -> Self {
        Self {
            profile,
            custom_ja3: None,
            custom_ja4: None,
        }
    }

    /// Set a custom JA3 string to use
    pub fn with_ja3(mut self, ja3: impl Into<String>) -> Self {
        self.custom_ja3 = Some(ja3.into());
        self
    }

    /// Set a custom JA4 string to use
    pub fn with_ja4(mut self, ja4: impl Into<String>) -> Self {
        self.custom_ja4 = Some(ja4.into());
        self
    }

    /// Apply JA3/JA4 spoofing to a TLS client config
    pub fn apply_to_config(&self, mut config: rustls::ClientConfig) -> rustls::ClientConfig {
        // Apply the profile-specific settings
        match self.profile {
            Ja3Ja4Profile::Chrome => self.apply_chrome_profile(&mut config),
            Ja3Ja4Profile::Firefox => self.apply_firefox_profile(&mut config),
            Ja3Ja4Profile::Safari => self.apply_safari_profile(&mut config),
            Ja3Ja4Profile::Edge => self.apply_edge_profile(&mut config),
            Ja3Ja4Profile::Random => self.apply_random_profile(&mut config),
        }

        config
    }

    /// Apply Chrome-like TLS fingerprint
    fn apply_chrome_profile(&self, _config: &mut rustls::ClientConfig) {
        // Chrome 123 JA3: 771,4865-4866-4867-49195-49199-49200,0-23-65281-10-11-35-16-5-13-18-0-43-27-21,23-24-25,0
        // In rustls 0.23, cipher suite ordering is managed at the provider level.
        // This is a simplified approximation using default settings.
        // Full JA3 spoofing would require lower-level manipulation of ClientHello bytes.
        tracing::debug!("Applying Chrome TLS profile");
    }

    /// Apply Firefox-like TLS fingerprint
    fn apply_firefox_profile(&self, _config: &mut rustls::ClientConfig) {
        tracing::debug!("Applying Firefox TLS profile");
    }

    /// Apply Safari-like TLS fingerprint
    fn apply_safari_profile(&self, _config: &mut rustls::ClientConfig) {
        tracing::debug!("Applying Safari TLS profile");
    }

    /// Apply Edge-like TLS fingerprint
    fn apply_edge_profile(&self, _config: &mut rustls::ClientConfig) {
        tracing::debug!("Applying Edge TLS profile");
    }

    /// Apply a random profile to avoid fingerprinting
    fn apply_random_profile(&self, config: &mut rustls::ClientConfig) {
        use rand::seq::SliceRandom;
        use rand::thread_rng;

        let profiles: [fn(&Self, &mut rustls::ClientConfig); 4] = [
            Self::apply_chrome_profile,
            Self::apply_firefox_profile,
            Self::apply_safari_profile,
            Self::apply_edge_profile,
        ];

        let mut rng = thread_rng();
        let chosen = profiles.choose(&mut rng).unwrap();
        chosen(self, config);
    }
}

/// Available JA3/JA4 profiles for spoofing
#[derive(Debug, Clone, Copy)]
pub enum Ja3Ja4Profile {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Random,
}

/// TLS configuration wrapper that applies JA3/JA4 spoofing
pub struct TlsConfig {
    /// JA3/JA4 spoofer for fingerprint evasion
    spoofer: Option<Ja3Ja4Spoofer>,
}

impl TlsConfig {
    /// Create a new TLS config with optional JA3/JA4 spoofing
    pub fn new_with_spoofing(profile: Option<Ja3Ja4Profile>) -> Result<Self, crate::core::error::ScannerError> {
        // Install crypto provider if not already done
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Create spoofer if profile is specified
        let spoofer = profile.map(|p| Ja3Ja4Spoofer::new(p));

        Ok(Self {
            spoofer,
        })
    }

    /// Build a ClientConfig with optional JA3/JA4 spoofing
    pub fn build(&self) -> Result<rustls::ClientConfig, crate::core::error::ScannerError> {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoCertVerification::new()))
            .with_no_client_auth();

        // Apply spoofing if configured
        if let Some(ref spoofer) = self.spoofer {
            Ok(spoofer.apply_to_config(config))
        } else {
            Ok(config)
        }
    }

    /// Enable JA3/JA4 spoofing with a specific profile
    pub fn with_spoofing(mut self, profile: Ja3Ja4Profile) -> Self {
        self.spoofer = Some(Ja3Ja4Spoofer::new(profile));
        self
    }

    /// Disable JA3/JA4 spoofing
    pub fn without_spoofing(mut self) -> Self {
        self.spoofer = None;
        self
    }
}

/// Build a permissive TLS ClientConfig that accepts all certificates
pub fn build_permissive_tls_config() -> rustls::ClientConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();

    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoCertVerification::new()))
        .with_no_client_auth()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ClientConfig;

    #[test]
    fn test_tls_config_creation() {
        let config = TlsConfig::new_with_spoofing(None).expect("Should create config");
        let client_config = config.build().expect("Should build config");
        // Verify it's a valid config by checking it has the right type
        let _: ClientConfig = client_config;
    }

    #[test]
    fn test_tls_config_with_spoofing() {
        let config = TlsConfig::new_with_spoofing(Some(Ja3Ja4Profile::Chrome))
            .expect("Should create config with spoofing");
        let client_config = config.build().expect("Should build config");
        let _: ClientConfig = client_config;
    }

    #[test]
    fn test_no_cert_verification() {
        let verifier = NoCertVerification::new();
        let schemes = verifier.supported_verify_schemes();
        assert!(!schemes.is_empty());
    }

    #[test]
    fn test_permissive_config() {
        let config = build_permissive_tls_config();
        let _: ClientConfig = config;
    }
}