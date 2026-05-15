//! Error types for MKPE operations

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MkpeError {
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] ed25519_dalek::SignatureError),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Bundle error: {0}")]
    BundleError(String),

    #[error("Manifest error: {0}")]
    ManifestError(String),

    #[error("Audit error: {0}")]
    AuditError(String),

    #[error("Hardware key error: {0}")]
    HardwareKeyError(String),
}

pub type Result<T> = std::result::Result<T, MkpeError>;
