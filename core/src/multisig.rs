//! Threshold multi-signature support for MKPE manifests
//!
//! Provides `MultiSignature` and `MultiSignatureManifest` for provenance
//! scenarios requiring approval from multiple independent keys.

use crate::{crypto::verify_signature, error::MkpeError, manifest::Manifest, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Information about a single signature in a multi-signature set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// Unique identifier for the signing key.
    pub key_id: String,
    /// Base64-encoded Ed25519 signature.
    pub signature: String,
    /// UTC timestamp when the signature was produced.
    pub timestamp: DateTime<Utc>,
}

/// A collection of signatures with a required threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSignature {
    /// Minimum number of valid signatures required.
    pub threshold: usize,
    /// Individual signatures contributing to the set.
    pub signatures: Vec<SignatureInfo>,
}

impl MultiSignature {
    /// Create a new empty multi-signature with the given threshold.
    pub fn new(threshold: usize) -> Self {
        Self {
            threshold,
            signatures: Vec::new(),
        }
    }
}

/// Wrapper that extends a [`Manifest`] with multi-signature support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSignatureManifest {
    /// The underlying manifest.
    pub manifest: Manifest,
    /// Multi-signature data attached to the manifest.
    pub multisig: MultiSignature,
}

impl MultiSignatureManifest {
    /// Create a new wrapper around an existing manifest.
    pub fn new(manifest: Manifest, threshold: usize) -> Self {
        Self {
            manifest,
            multisig: MultiSignature::new(threshold),
        }
    }

    /// Sign the embedded manifest with a keypair and append the signature.
    pub fn add_signature(&mut self, keypair: &dyn crate::crypto::Signer) -> Result<()> {
        let canonical = canonical_manifest_json(&self.manifest)?;
        let sig = keypair.sign(canonical.as_bytes())?;
        self.multisig.signatures.push(SignatureInfo {
            key_id: keypair.key_id(),
            signature: sig,
            timestamp: Utc::now(),
        });
        Ok(())
    }

    /// Verify the multi-signature against a set of trusted public keys.
    pub fn verify(&self, trusted_keys: &[String]) -> Result<bool> {
        verify_multisig(&self.manifest, &self.multisig, trusted_keys)
    }
}

/// Verify whether a [`MultiSignature`] meets its threshold for a given [`Manifest`].
///
/// Each signature is checked against the provided `trusted_keys` (base64-encoded
/// public keys). A signature counts toward the threshold only if it validates
/// with a *different* trusted key — a single key cannot satisfy the threshold
/// by signing multiple times.
///
/// # Errors
///
/// Returns an error only if manifest canonicalisation fails. Individual
/// signature decode or verification failures are treated as invalid signatures
/// and do **not** abort the overall check.
pub fn verify_multisig(
    manifest: &Manifest,
    multisig: &MultiSignature,
    trusted_keys: &[String],
) -> Result<bool> {
    if multisig.threshold == 0 {
        return Ok(true);
    }

    if multisig.signatures.is_empty() {
        return Ok(false);
    }

    let canonical = canonical_manifest_json(manifest)?;
    let data = canonical.as_bytes();

    let mut used_keys = vec![false; trusted_keys.len()];
    let mut valid_count = 0usize;

    for sig_info in &multisig.signatures {
        for (idx, key) in trusted_keys.iter().enumerate() {
            if used_keys[idx] {
                continue;
            }

            match verify_signature(key, data, &sig_info.signature) {
                Ok(true) => {
                    used_keys[idx] = true;
                    valid_count += 1;
                    break;
                }
                Ok(false) | Err(_) => {
                    // Invalid signature or malformed data — continue checking
                    // other keys.
                }
            }
        }

        if valid_count >= multisig.threshold {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Produce the canonical JSON bytes used for manifest signing/verification.
fn canonical_manifest_json(manifest: &Manifest) -> Result<String> {
    let manifest_data = serde_json::json!({
        "schema_version": manifest.schema_version,
        "engine_version": manifest.engine_version,
        "manifest_id": manifest.manifest_id,
        "bundle_root_hash": manifest.bundle_root_hash,
        "proof_count": manifest.proof_count,
        "verifier_public_key": manifest.verifier_public_key,
        "parent_manifest_id": manifest.parent_manifest_id,
        "metadata": manifest.metadata,
    });
    serde_json::to_string(&manifest_data)
        .map_err(|e| MkpeError::BundleError(format!("Manifest serialization failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;
    use crate::manifest::Manifest;

    fn test_manifest() -> Manifest {
        Manifest::new(
            "test_root_hash".to_string(),
            3,
            "test_public_key".to_string(),
            None,
        )
    }

    #[test]
    fn test_threshold_met() -> Result<()> {
        let manifest = test_manifest();
        let mut msm = MultiSignatureManifest::new(manifest, 2);

        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let kp3 = generate_keypair();

        msm.add_signature(&kp1)?;
        msm.add_signature(&kp2)?;
        msm.add_signature(&kp3)?;

        let trusted = vec![
            kp1.public_key.clone(),
            kp2.public_key.clone(),
            kp3.public_key.clone(),
        ];

        assert!(msm.verify(&trusted)?);
        Ok(())
    }

    #[test]
    fn test_threshold_not_met() -> Result<()> {
        let manifest = test_manifest();
        let mut msm = MultiSignatureManifest::new(manifest, 3);

        let kp1 = generate_keypair();
        let kp2 = generate_keypair();

        msm.add_signature(&kp1)?;
        msm.add_signature(&kp2)?;

        let trusted = vec![kp1.public_key.clone(), kp2.public_key.clone()];

        assert!(!msm.verify(&trusted)?);
        Ok(())
    }

    #[test]
    fn test_invalid_signature_in_set() -> Result<()> {
        let manifest = test_manifest();
        let mut msm = MultiSignatureManifest::new(manifest, 2);

        let kp1 = generate_keypair();
        let kp2 = generate_keypair();

        msm.add_signature(&kp1)?;
        msm.add_signature(&kp2)?;

        // Inject an invalid signature into the set.
        msm.multisig.signatures.push(SignatureInfo {
            key_id: "bad-key".to_string(),
            signature: "notavalidsignature==".to_string(),
            timestamp: Utc::now(),
        });

        let trusted = vec![kp1.public_key.clone(), kp2.public_key.clone()];

        // Threshold is still met by the two valid signatures.
        assert!(msm.verify(&trusted)?);
        Ok(())
    }

    #[test]
    fn test_empty_signatures() -> Result<()> {
        let manifest = test_manifest();
        let msm = MultiSignatureManifest::new(manifest, 1);

        let kp1 = generate_keypair();
        let trusted = vec![kp1.public_key.clone()];

        assert!(!msm.verify(&trusted)?);
        Ok(())
    }

    #[test]
    fn test_single_key_cannot_count_twice() -> Result<()> {
        let manifest = test_manifest();
        let mut msm = MultiSignatureManifest::new(manifest, 2);

        let kp1 = generate_keypair();

        msm.add_signature(&kp1)?;
        msm.add_signature(&kp1)?; // sign twice with same key

        let trusted = vec![kp1.public_key.clone()];

        // Only one unique key signed, so threshold 2 is not met.
        assert!(!msm.verify(&trusted)?);
        Ok(())
    }

    #[test]
    fn test_zero_threshold_always_passes() -> Result<()> {
        let manifest = test_manifest();
        let msm = MultiSignatureManifest::new(manifest, 0);

        // No signatures and no trusted keys needed.
        assert!(msm.verify(&[])?);
        Ok(())
    }
}
