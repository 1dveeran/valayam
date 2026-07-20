use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

pub struct PluginCrypto;

impl PluginCrypto {
    /// Generates a new ED25519 keypair, returning (private_key_bytes, public_key_bytes)
    pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        (signing_key.to_bytes(), verifying_key.to_bytes())
    }

    /// Signs a payload and returns the signature bytes
    pub fn sign(private_key: &[u8; 32], message: &[u8]) -> anyhow::Result<[u8; 64]> {
        let signing_key = SigningKey::from_bytes(private_key);
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes())
    }

    /// Verifies a signature for a payload against a public key
    pub fn verify(public_key: &[u8; 32], message: &[u8], signature_bytes: &[u8; 64]) -> anyhow::Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| anyhow::anyhow!("Invalid public key format: {}", e))?;
        let signature = Signature::from_bytes(signature_bytes);
        
        match verifying_key.verify(message, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
