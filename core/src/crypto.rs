//! Cryptographic primitives for MKPE
//!
//! Provides Ed25519 signing and verification

use crate::{MkpeError, Result};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Signer as EdSigner, Verifier, VerifyingKey};
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
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);

        let signature = signing_key.sign(data);
        Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
    }

    /// Verify a signature with this key pair's public key
    pub fn verify(&self, data: &[u8], signature_b64: &str) -> Result<bool> {
        verify_signature(&self.public_key, data, signature_b64)
    }
}

/// Supported signing algorithms
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Algorithm {
    Ed25519,
}

/// Physical backend that holds the private key material
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum KeyBackend {
    Software,
    TpmSealed,
    YubiKeyHmac,
}

/// Abstraction over any signing backend (software, TPM, YubiKey, etc.)
pub trait Signer: Send + Sync {
    /// Sign data and return a base64-encoded signature
    fn sign(&self, data: &[u8]) -> Result<String>;
    /// Return the base64-encoded public key
    fn public_key(&self) -> Result<String>;
    /// Unique key identifier
    fn key_id(&self) -> String;
    /// Cryptographic algorithm used
    fn algorithm(&self) -> Algorithm;
    /// Physical backend type
    fn backend(&self) -> KeyBackend;
}

impl Signer for KeyPair {
    fn sign(&self, data: &[u8]) -> Result<String> {
        self.sign(data)
    }

    fn public_key(&self) -> Result<String> {
        Ok(self.public_key.clone())
    }

    fn key_id(&self) -> String {
        self.key_id.clone()
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn backend(&self) -> KeyBackend {
        KeyBackend::Software
    }
}

/// Generate a new Ed25519 key pair
pub fn generate_keypair() -> KeyPair {
    let mut csprng = OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
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
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);

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

    #[test]
    fn test_signing_key_software_signs_and_verifies() -> Result<()> {
        let kp = generate_keypair();
        let sk = SigningKey::Software(kp.clone());
        let data = b"test data";
        let sig = sk.sign(data)?;
        assert!(kp.verify(data, &sig)?);
        assert!(!kp.verify(b"wrong", &sig)?);
        Ok(())
    }

    #[test]
    fn test_signing_key_with_key_id() {
        let kp = generate_keypair();
        let sk = SigningKey::Software(kp).with_key_id("new-id".to_string());
        assert_eq!(sk.key_id(), "new-id");
    }

    #[test]
    fn test_load_signing_key_fallback_to_keypair() -> Result<()> {
        use tempfile::NamedTempFile;
        let temp_file = NamedTempFile::new()?;
        let kp = generate_keypair();
        let json = serde_json::to_string(&kp)?;
        std::fs::write(temp_file.path(), &json)?;
        let loaded = load_signing_key(temp_file.path())?;
        assert_eq!(loaded.backend(), KeyBackend::Software);
        assert_eq!(loaded.public_key()?, kp.public_key);
        Ok(())
    }

    #[test]
    fn test_tpm_sealed_key_sign_fails_without_tpm() {
        let tk = TpmSealedKey {
            public_key: "test".to_string(),
            key_id: "test".to_string(),
            nv_index: 0x01C40001,
        };
        let result = tk.sign(b"data");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("TPM") || err.contains("Hardware key error"), "err={}", err);
    }

    #[test]
    fn test_yubikey_hmac_key_sign_fails_without_yubikey() {
        let yk = YubiKeyHmacKey {
            public_key: "test".to_string(),
            key_id: "test".to_string(),
            yubikey_serial: 0,
            challenge: vec![0u8; 64],
        };
        let result = yk.sign(b"data");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("YubiKey") || err.contains("Hardware key error"), "err={}", err);
    }
}

// ------------------------------------------------------------------
// SigningKey enum — serializable wrapper for any backend
// ------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", content = "data")]
pub enum SigningKey {
    Software(KeyPair),
    TpmSealed(TpmSealedKey),
    YubiKeyHmac(YubiKeyHmacKey),
}

impl Signer for SigningKey {
    fn sign(&self, data: &[u8]) -> Result<String> {
        match self {
            SigningKey::Software(kp) => kp.sign(data),
            SigningKey::TpmSealed(tpm) => tpm.sign(data),
            SigningKey::YubiKeyHmac(yk) => yk.sign(data),
        }
    }

    fn public_key(&self) -> Result<String> {
        match self {
            SigningKey::Software(kp) => Ok(kp.public_key.clone()),
            SigningKey::TpmSealed(tpm) => Ok(tpm.public_key.clone()),
            SigningKey::YubiKeyHmac(yk) => Ok(yk.public_key.clone()),
        }
    }

    fn key_id(&self) -> String {
        match self {
            SigningKey::Software(kp) => kp.key_id.clone(),
            SigningKey::TpmSealed(tpm) => tpm.key_id.clone(),
            SigningKey::YubiKeyHmac(yk) => yk.key_id.clone(),
        }
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn backend(&self) -> KeyBackend {
        match self {
            SigningKey::Software(_) => KeyBackend::Software,
            SigningKey::TpmSealed(_) => KeyBackend::TpmSealed,
            SigningKey::YubiKeyHmac(_) => KeyBackend::YubiKeyHmac,
        }
    }
}

impl From<KeyPair> for SigningKey {
    fn from(kp: KeyPair) -> Self {
        SigningKey::Software(kp)
    }
}

impl SigningKey {
    /// Return a new `SigningKey` with the given `key_id`, preserving all other fields.
    pub fn with_key_id(mut self, key_id: String) -> Self {
        match &mut self {
            SigningKey::Software(kp) => kp.key_id = key_id,
            SigningKey::TpmSealed(tk) => tk.key_id = key_id,
            SigningKey::YubiKeyHmac(yk) => yk.key_id = key_id,
        }
        self
    }
}

// ------------------------------------------------------------------
// TPM 2.0 sealed key — private key stored in TPM NV memory
// ------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmSealedKey {
    pub public_key: String,
    pub key_id: String,
    pub nv_index: u32,
}

#[cfg(feature = "tpm")]
impl Signer for TpmSealedKey {
    fn sign(&self, data: &[u8]) -> Result<String> {
        use tss_esapi::{Context, TctiNameConf};
        use tss_esapi::handles::NvIndexTpmHandle;
        use tss_esapi::interface_types::resource_handles::NvAuth;
        use zeroize::Zeroize;

        let tcti = TctiNameConf::from_environment_variable()
            .unwrap_or_else(|_| {
                "/dev/tpmrm0".parse()
                    .unwrap_or_else(|_| TctiNameConf::Device(Default::default()))
            });

        let mut context = Context::new(tcti)
            .map_err(|e| MkpeError::HardwareKeyError(format!("TPM context failed: {e}")))?;

        let nv_tpm_handle = NvIndexTpmHandle::new(self.nv_index)
            .map_err(|e| MkpeError::HardwareKeyError(format!("Invalid NV index: {e}")))?;

        let object_handle = context.tr_from_tpm_public(nv_tpm_handle.into())
            .map_err(|e| MkpeError::HardwareKeyError(format!("TPM handle conversion failed: {e}")))?;

        let nv_handle = tss_esapi::handles::NvIndexHandle::from(object_handle);

        let private_key_buffer = context.nv_read(NvAuth::Owner, nv_handle, 32, 0)
            .map_err(|e| MkpeError::HardwareKeyError(format!("TPM NV read failed: {e}")))?;

        let private_key_bytes = private_key_buffer.value();

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(private_key_bytes);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
        let signature = signing_key.sign(data);
        let sig_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

        key_array.zeroize();
        signing_key.to_bytes().zeroize();

        Ok(sig_b64)
    }

    fn public_key(&self) -> Result<String> {
        Ok(self.public_key.clone())
    }

    fn key_id(&self) -> String {
        self.key_id.clone()
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn backend(&self) -> KeyBackend {
        KeyBackend::TpmSealed
    }
}

#[cfg(not(feature = "tpm"))]
impl Signer for TpmSealedKey {
    fn sign(&self, _data: &[u8]) -> Result<String> {
        Err(MkpeError::HardwareKeyError(
            "TPM support not compiled in".to_string(),
        ))
    }

    fn public_key(&self) -> Result<String> { Ok(self.public_key.clone()) }
    fn key_id(&self) -> String { self.key_id.clone() }
    fn algorithm(&self) -> Algorithm { Algorithm::Ed25519 }
    fn backend(&self) -> KeyBackend { KeyBackend::TpmSealed }
}

// ------------------------------------------------------------------
// YubiKey HMAC-derived key — Ed25519 seed derived from HMAC response
// ------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YubiKeyHmacKey {
    pub public_key: String,
    pub key_id: String,
    pub yubikey_serial: u32,
    pub challenge: Vec<u8>,
}

#[cfg(feature = "yubikey")]
impl Signer for YubiKeyHmacKey {
    fn sign(&self, data: &[u8]) -> Result<String> {
        use challenge_response::ChallengeResponse;
        use challenge_response::config::{Config, Mode, Slot};
        use hkdf::Hkdf;
        use sha2::Sha256;
        use zeroize::Zeroize;

        let mut cr = ChallengeResponse::new()
            .map_err(|e| MkpeError::HardwareKeyError(format!("YubiKey init failed: {e}")))?;

        let device = cr.find_device_from_serial(self.yubikey_serial)
            .map_err(|e| MkpeError::HardwareKeyError(format!("YubiKey find failed: {e}")))?;

        let config = Config::new_from(device)
            .set_mode(Mode::Sha1)
            .set_slot(Slot::Slot2);

        let hmac = cr.challenge_response_hmac(&self.challenge, config)
            .map_err(|e| MkpeError::HardwareKeyError(format!("YubiKey HMAC failed: {e}")))?;

        let hk = Hkdf::<Sha256>::new(Some(&self.challenge), &*hmac);
        let mut seed = [0u8; 32];
        hk.expand(b"mkpe-ed25519", &mut seed)
            .map_err(|e| MkpeError::HardwareKeyError(format!("HKDF failed: {e}")))?;

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let signature = signing_key.sign(data);
        let sig_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

        seed.zeroize();
        signing_key.to_bytes().zeroize();

        Ok(sig_b64)
    }

    fn public_key(&self) -> Result<String> {
        Ok(self.public_key.clone())
    }

    fn key_id(&self) -> String {
        self.key_id.clone()
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn backend(&self) -> KeyBackend {
        KeyBackend::YubiKeyHmac
    }
}

#[cfg(not(feature = "yubikey"))]
impl Signer for YubiKeyHmacKey {
    fn sign(&self, _data: &[u8]) -> Result<String> {
        Err(MkpeError::HardwareKeyError(
            "YubiKey support not compiled in".to_string(),
        ))
    }

    fn public_key(&self) -> Result<String> { Ok(self.public_key.clone()) }
    fn key_id(&self) -> String { self.key_id.clone() }
    fn algorithm(&self) -> Algorithm { Algorithm::Ed25519 }
    fn backend(&self) -> KeyBackend { KeyBackend::YubiKeyHmac }
}

// ------------------------------------------------------------------
// Key loading / generation helpers
// ------------------------------------------------------------------

/// Load a signing key from a JSON file.
///
/// Tries the new `SigningKey` format first, then falls back to legacy `KeyPair`.
pub fn load_signing_key(path: &std::path::Path) -> Result<SigningKey> {
    let content = std::fs::read_to_string(path)
        .map_err(MkpeError::IoError)?;

    // Try new format first
    if let Ok(sk) = serde_json::from_str::<SigningKey>(&content) {
        return Ok(sk);
    }

    // Fall back to legacy KeyPair format
    let kp: KeyPair = serde_json::from_str(&content)
        .map_err(|e| MkpeError::HardwareKeyError(format!("Invalid key file: {e}")))?;
    Ok(SigningKey::Software(kp))
}

/// Generate a new software signing key.
pub fn generate_software_key() -> SigningKey {
    SigningKey::Software(generate_keypair())
}

/// Generate a TPM-backed signing key.
#[cfg(feature = "tpm")]
pub fn generate_tpm_key() -> Result<SigningKey> {
    use tss_esapi::{Context, TctiNameConf};
    use tss_esapi::handles::NvIndexTpmHandle;
    use tss_esapi::structures::NvPublicBuilder;
    use tss_esapi::attributes::NvIndexAttributes;
    use tss_esapi::interface_types::resource_handles::{Provision, NvAuth};
    use rand::RngCore;
    use zeroize::Zeroize;

    let tcti = TctiNameConf::from_environment_variable()
        .unwrap_or_else(|_| {
            "/dev/tpmrm0".parse()
                .unwrap_or_else(|_| TctiNameConf::Device(Default::default()))
        });

    let mut context = Context::new(tcti)
        .map_err(|e| MkpeError::HardwareKeyError(format!("TPM context failed: {e}")))?;

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let public_key = general_purpose::STANDARD.encode(verifying_key.to_bytes());
    let key_id = uuid::Uuid::new_v4().to_string();

    let nv_index = 0x01C40001u32;
    let nv_tpm_handle = NvIndexTpmHandle::new(nv_index)
        .map_err(|e| MkpeError::HardwareKeyError(format!("Invalid NV index: {e}")))?;

    let nv_attrs = tss_esapi::attributes::NvIndexAttributesBuilder::new()
        .with_owner_read(true)
        .with_owner_write(true)
        .build()
        .map_err(|e| MkpeError::HardwareKeyError(format!("NV attributes failed: {e}")))?;
    let nv_public = NvPublicBuilder::new()
        .with_nv_index(nv_tpm_handle)
        .with_data_area_size(32)
        .with_index_attributes(nv_attrs)
        .build()
        .map_err(|e| MkpeError::HardwareKeyError(format!("NV public build failed: {e}")))?;

    let nv_handle = context.nv_define_space(Provision::Owner, None, nv_public)
        .map_err(|e| MkpeError::HardwareKeyError(format!("TPM define space failed: {e}")))?;

    let data_buffer = tss_esapi::structures::MaxNvBuffer::try_from(seed.to_vec())
        .map_err(|e| MkpeError::HardwareKeyError(format!("Buffer conversion failed: {e}")))?;
    context.nv_write(NvAuth::Owner, nv_handle, data_buffer, 0)
        .map_err(|e| MkpeError::HardwareKeyError(format!("TPM NV write failed: {e}")))?;

    seed.zeroize();

    Ok(SigningKey::TpmSealed(TpmSealedKey {
        public_key,
        key_id,
        nv_index,
    }))
}

#[cfg(not(feature = "tpm"))]
pub fn generate_tpm_key() -> Result<SigningKey> {
    Err(MkpeError::HardwareKeyError(
        "TPM support not compiled in".to_string(),
    ))
}

/// Generate a YubiKey-backed signing key.
#[cfg(feature = "yubikey")]
pub fn generate_yubikey_key() -> Result<SigningKey> {
    use challenge_response::ChallengeResponse;
    use challenge_response::config::{Config, Mode, Slot};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use rand::RngCore;
    use zeroize::Zeroize;

    let mut cr = ChallengeResponse::new()
        .map_err(|e| MkpeError::HardwareKeyError(format!("YubiKey init failed: {e}")))?;

    let device = cr.find_device()
        .map_err(|e| MkpeError::HardwareKeyError(format!("YubiKey not found: {e}")))?;

    let serial = device.serial
        .ok_or_else(|| MkpeError::HardwareKeyError("YubiKey serial unavailable".to_string()))?;

    let mut challenge = vec![0u8; 64];
    rand::thread_rng().fill_bytes(&mut challenge);

    let config = Config::new_from(device)
        .set_mode(Mode::Sha1)
        .set_slot(Slot::Slot2);

    let hmac = cr.challenge_response_hmac(&challenge, config)
        .map_err(|e| MkpeError::HardwareKeyError(format!("YubiKey HMAC failed: {e}")))?;

    let hk = Hkdf::<Sha256>::new(Some(&challenge), &*hmac);
    let mut seed = [0u8; 32];
    hk.expand(b"mkpe-ed25519", &mut seed)
        .map_err(|e| MkpeError::HardwareKeyError(format!("HKDF failed: {e}")))?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let public_key = general_purpose::STANDARD.encode(verifying_key.to_bytes());
    let key_id = uuid::Uuid::new_v4().to_string();

    seed.zeroize();

    Ok(SigningKey::YubiKeyHmac(YubiKeyHmacKey {
        public_key,
        key_id,
        yubikey_serial: serial,
        challenge,
    }))
}

#[cfg(not(feature = "yubikey"))]
pub fn generate_yubikey_key() -> Result<SigningKey> {
    Err(MkpeError::HardwareKeyError(
        "YubiKey support not compiled in".to_string(),
    ))
}
