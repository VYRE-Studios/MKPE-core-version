//! Cryptographic primitives for MKPE
//!
//! Provides Ed25519 signing and verification

use crate::{MkpeError, Result};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// Cryptographic key pair for signing operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// Base64-encoded private key
    pub private_key: String,
    /// Base64-encoded public key
    pub public_key: String,
    /// Unique key identifier
    pub key_id: String,
}

impl KeyPair {
    /// Create a new key pair from existing keys
    pub fn new(private_key: String, public_key: String, key_id: String) -> Self {
        Self {
            private_key,
            public_key,
            key_id,
        }
    }

    /// Sign data with this key pair
    pub fn sign(&self, data: &[u8]) -> Result<String> {
        let key_bytes = general_purpose::STANDARD.decode(&self.private_key)?;
        if key_bytes.len() != 32 {
            return Err(MkpeError::InvalidKeyFormat(
                "Private key must be 32 bytes".to_string(),
            ));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        let signing_key = SigningKey::from_bytes(&key_array);

        let signature = signing_key.sign(data);
        Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
    }

    /// Verify a signature with this key pair's public key
    pub fn verify(&self, data: &[u8], signature_b64: &str) -> Result<bool> {
        verify_signature(&self.public_key, data, signature_b64)
    }
}

/// Generate a new Ed25519 key pair
pub fn generate_keypair() -> KeyPair {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let private_key = general_purpose::STANDARD.encode(signing_key.to_bytes());
    let public_key = general_purpose::STANDARD.encode(verifying_key.to_bytes());
    let key_id = uuid::Uuid::new_v4().to_string();

    KeyPair {
        private_key,
        public_key,
        key_id,
    }
}

/// Sign data with a base64-encoded private key
pub fn sign_data(private_key_b64: &str, data: &[u8]) -> Result<String> {
    let key_bytes = general_purpose::STANDARD.decode(private_key_b64)?;
    if key_bytes.len() != 32 {
        return Err(MkpeError::InvalidKeyFormat(
            "Private key must be 32 bytes".to_string(),
        ));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes(&key_array);

    let signature = signing_key.sign(data);
    Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
}

/// Verify a signature with a base64-encoded public key
pub fn verify_signature(public_key_b64: &str, data: &[u8], signature_b64: &str) -> Result<bool> {
    let key_bytes = general_purpose::STANDARD.decode(public_key_b64)?;
    let sig_bytes = general_purpose::STANDARD.decode(signature_b64)?;

    if key_bytes.len() != 32 {
        return Err(MkpeError::InvalidKeyFormat(
            "Public key must be 32 bytes".to_string(),
        ));
    }
    if sig_bytes.len() != 64 {
        return Err(MkpeError::InvalidKeyFormat(
            "Signature must be 64 bytes".to_string(),
        ));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    let verifying_key = VerifyingKey::from_bytes(&key_array)?;

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_array);

    Ok(verifying_key.verify(data, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair();
        assert!(!keypair.private_key.is_empty());
        assert!(!keypair.public_key.is_empty());
        assert!(!keypair.key_id.is_empty());
        assert_ne!(keypair.private_key, keypair.public_key);
    }

    #[test]
    fn test_sign_and_verify() -> Result<()> {
        let keypair = generate_keypair();
        let data = b"Hello, MKPE!";

        let signature = keypair.sign(data)?;
        let is_valid = keypair.verify(data, &signature)?;

        assert!(is_valid);

        // Test with wrong data
        let is_invalid = keypair.verify(b"Wrong data", &signature)?;
        assert!(!is_invalid);

        Ok(())
    }
}
