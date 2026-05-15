//! Sigstore keyless signing via the upstream `cosign` CLI.
//!
//! MKPE does not parse Fulcio certificates or Rekor inclusion proofs itself;
//! it shells out to `cosign sign-blob` / `cosign verify-blob` with a bundle
//! file, per workspace policy.

use crate::{MkpeError, Result};
use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;
use std::io::Write;
use std::process::Command;
use uuid::Uuid;

use super::signing::{ProvenanceSigner, SigAlgorithm, SignatureMaterial};

/// Signs DSSE PAE bytes using `cosign sign-blob` (ambient OIDC on GitHub
/// Actions, or other cosign-supported identity elsewhere).
#[derive(Debug, Clone)]
pub struct CosignCliKeylessSigner {
    /// Placed in the DSSE `keyid` field; must match the Fulcio certificate
    /// identity policy used at verification time (typically `builder.id`).
    builder_identity: String,
}

impl CosignCliKeylessSigner {
    pub fn new(builder_identity: impl Into<String>) -> Self {
        Self {
            builder_identity: builder_identity.into(),
        }
    }
}

impl ProvenanceSigner for CosignCliKeylessSigner {
    fn algorithm(&self) -> SigAlgorithm {
        SigAlgorithm::EcdsaP256Sha256
    }

    fn key_id(&self) -> &str {
        &self.builder_identity
    }

    fn sign_pae(&self, pae: &[u8]) -> Result<SignatureMaterial> {
        let work = std::env::temp_dir().join(format!("mkpe-cosign-sign-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&work).map_err(MkpeError::IoError)?;
        let blob_path = work.join("dsse-pae.bin");
        let bundle_path = work.join("bundle.json");
        std::fs::write(&blob_path, pae).map_err(MkpeError::IoError)?;

        let output = Command::new("cosign")
            .args([
                "sign-blob",
                "--yes",
                "--bundle",
                bundle_path.to_str().ok_or_else(|| {
                    MkpeError::ProvenanceError("bundle path is not valid UTF-8".into())
                })?,
                blob_path.to_str().ok_or_else(|| {
                    MkpeError::ProvenanceError("blob path is not valid UTF-8".into())
                })?,
            ])
            .output()
            .map_err(|e| {
                MkpeError::ProvenanceError(format!(
                    "failed to spawn `cosign` (is it installed and on PATH?): {e}"
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let _ = std::fs::remove_dir_all(&work);
            return Err(MkpeError::ProvenanceError(format!(
                "`cosign sign-blob` exited with {}: {stderr}",
                output.status
            )));
        }

        let bundle_text = std::fs::read_to_string(&bundle_path).map_err(|e| {
            let _ = std::fs::remove_dir_all(&work);
            MkpeError::IoError(e)
        })?;
        let _ = std::fs::remove_dir_all(&work);

        let bundle: Value =
            serde_json::from_str(&bundle_text).map_err(|e| MkpeError::ProvenanceError(format!(
                "cosign wrote a bundle file that is not valid JSON: {e}"
            )))?;

        let (signature, cert_pem) = extract_sig_from_bundle(&bundle)?;

        Ok(SignatureMaterial {
            algorithm: SigAlgorithm::EcdsaP256Sha256,
            key_id: self.builder_identity.clone(),
            signature,
            cert_chain_pem: cert_pem,
            sigstore_bundle: Some(bundle),
        })
    }
}

/// Run `cosign verify-blob` on DSSE PAE bytes using a saved bundle JSON.
pub fn verify_blob_with_cosign(
    pae: &[u8],
    bundle: &Value,
    certificate_identity: &str,
    certificate_oidc_issuer: &str,
) -> Result<()> {
    let work = std::env::temp_dir().join(format!("mkpe-cosign-verify-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&work).map_err(MkpeError::IoError)?;
    let blob_path = work.join("dsse-pae.bin");
    let bundle_path = work.join("bundle.json");
    std::fs::write(&blob_path, pae).map_err(MkpeError::IoError)?;
    let mut f = std::fs::File::create(&bundle_path).map_err(MkpeError::IoError)?;
    serde_json::to_writer(&mut f, bundle).map_err(MkpeError::JsonError)?;
    f.flush().map_err(MkpeError::IoError)?;

    let output = Command::new("cosign")
        .args([
            "verify-blob",
            "--bundle",
            bundle_path.to_str().ok_or_else(|| {
                MkpeError::ProvenanceError("bundle path is not valid UTF-8".into())
            })?,
            "--certificate-identity",
            certificate_identity,
            "--certificate-oidc-issuer",
            certificate_oidc_issuer,
            blob_path.to_str().ok_or_else(|| {
                MkpeError::ProvenanceError("blob path is not valid UTF-8".into())
            })?,
        ])
        .output()
        .map_err(|e| {
            MkpeError::ProvenanceError(format!(
                "failed to spawn `cosign` (is it installed and on PATH?): {e}"
            ))
        })?;

    let _ = std::fs::remove_dir_all(&work);

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(MkpeError::VerificationFailed(format!(
            "`cosign verify-blob` failed: {stderr}"
        )))
    }
}

fn extract_sig_from_bundle(bundle: &Value) -> Result<(Vec<u8>, Option<String>)> {
    let msg_sig = bundle_message_signature(bundle).ok_or_else(|| {
        MkpeError::ProvenanceError(
            "Sigstore bundle missing messageSignature (unsupported bundle shape)".into(),
        )
    })?;
    let sig_b64 = msg_sig
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            MkpeError::ProvenanceError(
                "Sigstore bundle messageSignature.signature missing or not a string".into(),
            )
        })?;
    let signature = general_purpose::STANDARD
        .decode(sig_b64.trim())
        .map_err(MkpeError::Base64Error)?;

    let certs = bundle_certificates_der(bundle)?;
    let cert_pem = if certs.is_empty() {
        None
    } else {
        let mut pem = String::new();
        for der in certs {
            pem.push_str(&pem_wrap_certificate(&der));
        }
        Some(pem)
    };

    Ok((signature, cert_pem))
}

fn bundle_message_signature(bundle: &Value) -> Option<&Value> {
    bundle
        .get("spec")
        .and_then(|s| s.get("messageSignature"))
        .or_else(|| bundle.get("messageSignature"))
}

fn bundle_certificates_der(bundle: &Value) -> Result<Vec<Vec<u8>>> {
    let vm = bundle
        .get("spec")
        .and_then(|s| s.get("verificationMaterial"))
        .or_else(|| bundle.get("verificationMaterial"))
        .ok_or_else(|| {
            MkpeError::ProvenanceError(
                "Sigstore bundle missing verificationMaterial".into(),
            )
        })?;
    let chain = vm
        .get("x509CertificateChain")
        .and_then(|c| c.get("certificates"))
        .and_then(|c| c.as_array())
        .ok_or_else(|| {
            MkpeError::ProvenanceError(
                "Sigstore bundle missing x509CertificateChain.certificates[]".into(),
            )
        })?;

    let mut out = Vec::with_capacity(chain.len());
    for entry in chain {
        let b64 = entry
            .get("rawBytes")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                MkpeError::ProvenanceError(
                    "certificate entry missing rawBytes (base64 DER)".into(),
                )
            })?;
        let der = general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(MkpeError::Base64Error)?;
        out.push(der);
    }
    Ok(out)
}

fn pem_wrap_certificate(der: &[u8]) -> String {
    let b64 = general_purpose::STANDARD.encode(der);
    let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(line).unwrap_or(""));
        s.push('\n');
    }
    s.push_str("-----END CERTIFICATE-----\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_message_signature_nested_and_flat() {
        let nested = serde_json::json!({
            "spec": { "messageSignature": { "signature": "QQ==" } }
        });
        assert!(bundle_message_signature(&nested).is_some());

        let flat = serde_json::json!({
            "messageSignature": { "signature": "QQ==" }
        });
        assert!(bundle_message_signature(&flat).is_some());
    }

    #[test]
    fn extract_sig_from_minimal_bundle() {
        let der = vec![0x30u8, 3u8, 1u8, 2u8, 3u8]; // not a real cert, enough for base64 round-trip
        let b64 = general_purpose::STANDARD.encode(&der);
        let bundle = serde_json::json!({
            "spec": {
                "messageSignature": { "signature": "dGVzdA==" },
                "verificationMaterial": {
                    "x509CertificateChain": {
                        "certificates": [ { "rawBytes": b64 } ]
                    }
                }
            }
        });
        let (sig, pem) = extract_sig_from_bundle(&bundle).expect("extract");
        assert_eq!(sig, b"test");
        assert!(pem.is_some());
        assert!(pem.unwrap().contains("BEGIN CERTIFICATE"));
    }
}
