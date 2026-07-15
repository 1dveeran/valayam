use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm, TokenData, errors::ErrorKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct DummyClaims {
    sub: String,
    exp: usize,
}

pub struct JwtCracker;

impl JwtCracker {
    /// Brute forces a JWT using a static dictionary of the top 100 most common weak secrets.
    pub fn crack_jwt_secret(token: &str) -> Option<String> {
        let dictionary = vec![
            "secret",
            "123456",
            "password",
            "admin",
            "12345",
            "secretkey",
            "supersecret",
            "changeme",
            "qwerty",
            "test",
            "test1234",
            "admin123",
            "token",
            "dev",
        ];

        let mut validation = Validation::new(Algorithm::HS256);
        validation.insecure_disable_signature_validation(); // First check if it's even valid structurally
        
        if decode::<serde_json::Value>(token, &DecodingKey::from_secret(b"dummy"), &validation).is_err() {
            return None; // Not a valid JWT structure
        }

        let strict_validation = Validation::new(Algorithm::HS256); // Requires valid signature

        for secret in dictionary {
            match decode::<serde_json::Value>(
                token,
                &DecodingKey::from_secret(secret.as_bytes()),
                &strict_validation,
            ) {
                Ok(_) => {
                    // Signature verified successfully with this secret!
                    return Some(secret.to_string());
                }
                Err(err) => {
                    if let ErrorKind::InvalidSignature = err.kind() {
                        continue;
                    } else if let ErrorKind::ExpiredSignature = err.kind() {
                        // It verified, but is expired. We still cracked the secret!
                        return Some(secret.to_string());
                    }
                }
            }
        }

        None
    }
}
