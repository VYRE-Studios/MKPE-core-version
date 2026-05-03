//! Dead Simple Signing Envelope (DSSE) support for MKPE
//!
//! Implements the DSSE v1.0 protocol for industry-standard provenance envelopes.
//! Signatures use Pre-Authentication Encoding (PAE) over the payload type
//! and serialized payload to prevent type confusion attacks.

use crate::crypto;
use crate::crypto::KeyPair;
use crate::manifest::Manifest;
use crate::{MkpeError, Result};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

/// Payload type for MKPE manifests inside a DSSE envelope.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.morse-kirby.manifest+json";

/// DSSE signature entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DSSSignature {
    /// Key identifier hint (unauthenticated).
    pub keyid: String,
    /// Base64-encoded signature.
    pub sig: String,
}

/// DSSE envelope containing a signed payload and one or more signatures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DSSEEnvelope {
    /// Base64-encoded payload.
    pub payload: String,
    /// Payload type (media type).
    pub payload_type: String,
    /// Signatures over the PAE-encoded payload.
    pub signatures: Vec<DSSSignature>,
}

/// Compute DSSE Pre-Authentication Encoding (PAE).
///
/// ```text
/// PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
/// SP              = ASCII space (0x20)
/// LEN(s)          = ASCII decimal encoding of the byte length of s, with no leading zeros
/// ```
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(b"DSSEv1 ");
    result.extend_from_slice(payload_type.len().to_string().as_bytes());
    result.extend_from_slice(b" ");
    result.extend_from_slice(payload_type.as_bytes());
    result.extend_from_slice(b" ");
    result.extend_from_slice(payload.len().to_string().as_bytes());
    result.extend_from_slice(b" ");
    result.extend_from_slice(payload);
    result
}

impl DSSEEnvelope {
    /// Create a DSSE envelope from a manifest, signing with the provided keypair.
    ///
    /// The manifest is serialized to canonical JSON, base64-encoded as the payload,
    /// and signed using DSSE PAE over `payload_type || serialized_body`.
    pub fn from_manifest(manifest: &Manifest, keypair: &KeyPair) -> Result<Self> {
        let serialized_body =
            serde_json::to_vec(manifest).map_err(|e| MkpeError::JsonError(e))?;
        let payload = general_purpose::STANDARD.encode(&serialized_body);

        let pae_bytes = pae(DSSE_PAYLOAD_TYPE, &serialized_body);
        let sig = keypair.sign(&pae_bytes)?;

        let signature = DSSSignature {
            keyid: keypair.key_id.clone(),
            sig,
        };

        Ok(Self {
            payload,
            payload_type: DSSE_PAYLOAD_TYPE.to_string(),
            signatures: vec![signature],
        })
    }

    /// Verify the envelope against a base64-encoded Ed25519 public key.
    ///
    /// Iterates over all signatures and returns `true` on the first valid
    /// signature. Returns `false` if no signature verifies.
    pub fn verify(&self, public_key: &str) -> Result<bool> {
        let serialized_body = general_purpose::STANDARD.decode(&self.payload)?;
        let pae_bytes = pae(&self.payload_type, &serialized_body);

        for signature in &self.signatures {
            let is_valid = crypto::verify_signature(public_key, &pae_bytes, &signature.sig)?;
            if is_valid {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Serialize envelope to a JSON string.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| MkpeError::JsonError(e))
    }

    /// Deserialize envelope from a JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| MkpeError::JsonError(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;
    use crate::manifest::Manifest;

    #[test]
    fn test_pae_encoding_matches_spec_vector() {
        // Official DSSE test vector:
        // body = "hello world" (11 bytes)
        // type = "http://example.com/HelloWorld" (29 bytes)
        // PAE  = "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        let body = b"hello world";
        let payload_type = "http://example.com/HelloWorld";
        let encoded = pae(payload_type, body);
        let expected = b"DSSEv1 29 http://example.com/HelloWorld 11 hello world";
        assert_eq!(
            encoded, expected,
            "PAE must match the DSSE v1.0 specification test vector"
        );
    }

    #[test]
    fn test_pae_empty_payload() {
        let encoded = pae("type", b"");
        assert_eq!(encoded, b"DSSEv1 4 type 0 ");
    }

    #[test]
    fn test_dsse_envelope_from_manifest_verifies_with_signing_key() -> Result<()> {
        let keypair = generate_keypair();
        let manifest = Manifest::new(
            "test_root_hash".to_string(),
            3,
            keypair.public_key.clone(),
            None,
        );

        let envelope = DSSEEnvelope::from_manifest(&manifest, &keypair)?;

        assert_eq!(envelope.payload_type, DSSE_PAYLOAD_TYPE);
        assert_eq!(envelope.signatures.len(), 1);
        assert!(!envelope.signatures[0].sig.is_empty());
        assert_eq!(envelope.signatures[0].keyid, keypair.key_id);

        let is_valid = envelope.verify(&keypair.public_key)?;
        assert!(is_valid, "envelope must verify with the signing public key");

        Ok(())
    }

    #[test]
    fn test_dsse_envelope_rejects_wrong_public_key() -> Result<()> {
        let keypair = generate_keypair();
        let wrong_keypair = generate_keypair();
        let manifest = Manifest::new(
            "test_root_hash".to_string(),
            3,
            keypair.public_key.clone(),
            None,
        );

        let envelope = DSSEEnvelope::from_manifest(&manifest, &keypair)?;
        let is_valid = envelope.verify(&wrong_keypair.public_key)?;
        assert!(!is_valid, "envelope must fail verification with an unrelated public key");

        Ok(())
    }

    #[test]
    fn test_dsse_envelope_json_roundtrip_preserves_verification() -> Result<()> {
        let keypair = generate_keypair();
        let manifest = Manifest::new(
            "test_root_hash".to_string(),
            5,
            keypair.public_key.clone(),
            None,
        );

        let envelope = DSSEEnvelope::from_manifest(&manifest, &keypair)?;
        let json = envelope.to_json()?;
        let restored = DSSEEnvelope::from_json(&json)?;

        assert_eq!(restored.payload, envelope.payload);
        assert_eq!(restored.payload_type, envelope.payload_type);
        assert_eq!(restored.signatures, envelope.signatures);

        let is_valid = restored.verify(&keypair.public_key)?;
        assert!(
            is_valid,
            "restored envelope must still verify after JSON roundtrip"
        );

        Ok(())
    }

    #[test]
    fn test_dsse_envelope_empty_signatures_returns_false() -> Result<()> {
        let envelope = DSSEEnvelope {
            payload: general_purpose::STANDARD.encode(b"{}"),
            payload_type: DSSE_PAYLOAD_TYPE.to_string(),
            signatures: vec![],
        };

        let is_valid = envelope.verify("dummy_key")?;
        assert!(!is_valid, "envelope with no signatures must return false");

        Ok(())
    }

    #[test]
    fn test_dsse_envelope_payload_type_constant() {
        assert_eq!(
            DSSE_PAYLOAD_TYPE,
            "application/vnd.morse-kirby.manifest+json"
        );
    }
}
