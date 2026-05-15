//! Signing-strategy abstraction for the provenance envelope.
//!
//! The Phase 1.5/1.6 producer was hard-coded to ed25519 local-file
//! signing because it was the only backend MKPE had. Phase 2 adds
//! Sigstore-keyless (Fulcio + Rekor) as the production identity model,
//! and a future expansion may add cloud-KMS-backed signing. Rather than
//! threading three separate `sign_*` methods through `Statement` and
//! every CLI/CI call site, all three are funneled through one trait
//! that knows how to sign a slice of DSSE PAE bytes.
//!
//! ## Invariants every backend must uphold
//!
//! 1. **Sign the PAE, not the payload.** The DSSE Pre-Authentication
//!    Encoding binds the payload type to the payload bytes. A backend
//!    that signs the raw payload silently allows payload-type confusion
//!    attacks. The producer builds the PAE in [`crate::provenance`];
//!    a signer treats the input as opaque bytes.
//! 2. **Return raw signature bytes, not base64.** The DSSE envelope's
//!    `sig` field is base64-encoded once, in `Statement::sign`. A
//!    backend that base64s internally creates a double-encoding bug
//!    that only surfaces during verification.
//! 3. **`key_id` is stable for the lifetime of the signing identity.**
//!    For local-file ed25519 this is the persisted `KeyPair::key_id`
//!    (a UUID). For Sigstore-keyless it will be the OIDC subject URI
//!    of the workflow identity (e.g.
//!    `https://github.com/VyreVault/mkpe/.github/workflows/release.yml@refs/tags/v1.1.0`).
//!    The verifier MUST treat unknown `key_id` values as opaque -- the
//!    trust decision lives one layer up, in the verification policy.
//! 4. **No clock calls inside `sign_pae`.** The PAE already contains
//!    the timestamps that belong in the statement. A signer that reads
//!    the clock makes the result non-reproducible.
//!
//! ## What this module does *not* abstract
//!
//! Verification for Sigstore keyless envelopes is delegated to the
//! `cosign verify-blob` CLI (see `cosign_cli`); MKPE does not walk Fulcio
//! chains or Rekor proofs in-process.

use crate::{KeyPair, MkpeError, Result};
use base64::{engine::general_purpose, Engine as _};

/// Signature algorithms MKPE will produce or accept inside a DSSE envelope.
///
/// Adding a variant here is a coordinated change: the JSON Schema's
/// `keyid` description and any verifier-side trust policy must be
/// updated in the same PR. Removing a variant is a breaking change
/// for every previously-issued attestation that referenced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigAlgorithm {
    /// Pure Ed25519 over the DSSE PAE. Default for Phase 1.5/1.6
    /// local-file builds. Signatures are deterministic per RFC 8032,
    /// which makes the envelope byte-stable across re-runs.
    Ed25519,

    /// ECDSA over secp256r1 with SHA-256 hashing. Reserved for Phase
    /// 2.2 Sigstore-keyless. ECDSA signatures are randomized, so the
    /// envelope is NOT byte-stable across re-runs even when the
    /// statement payload is; reproducibility checks must compare the
    /// canonical statement bytes, never the envelope.
    EcdsaP256Sha256,
}

impl SigAlgorithm {
    /// Stable wire tag suitable for logs and the future DSSE
    /// `algorithm` extension. We do not put this string in the
    /// signature itself; `keyid` carries the identity, and the
    /// algorithm is inferred from the key material at verification.
    pub const fn as_str(self) -> &'static str {
        match self {
            SigAlgorithm::Ed25519 => "ed25519",
            SigAlgorithm::EcdsaP256Sha256 => "ecdsa-p256-sha256",
        }
    }
}

/// Result of one signing call. Carries the raw signature bytes plus
/// any backend-specific evidence that must round-trip into the DSSE
/// envelope.
///
/// `cert_chain_pem` is `None` for local-key backends and `Some` for
/// Sigstore-keyless, where the verifier walks the chain to a trusted
/// Fulcio root before accepting the signature. A KMS backend may also
/// emit `None` (the verifier uses the out-of-band public key).
#[derive(Debug, Clone)]
pub struct SignatureMaterial {
    pub algorithm: SigAlgorithm,
    pub key_id: String,
    /// Raw signature bytes. The DSSE envelope encodes them base64
    /// exactly once; double-encoding is a backend bug we surface by
    /// rejecting any input that's already base64-looking when we
    /// haven't decoded it ourselves.
    pub signature: Vec<u8>,
    /// PEM-encoded leaf-and-intermediates cert chain. Populated only
    /// by Sigstore-keyless. `None` everywhere else.
    pub cert_chain_pem: Option<String>,
    /// Full Sigstore bundle JSON from `cosign sign-blob --bundle`, when
    /// applicable. Required for `cosign verify-blob` at verification time.
    pub sigstore_bundle: Option<serde_json::Value>,
}

/// Strategy-pattern interface for producing one DSSE signature.
///
/// Implementations are stateless from `&self`'s perspective -- the
/// signer captures whatever credential context it needs at
/// construction time (a `KeyPair`, an OIDC token, a KMS client
/// handle) and exposes only the act of signing. The producer never
/// asks a signer to fetch or refresh credentials mid-build; that is a
/// constructor-time concern.
///
/// The trait is object-safe (`&dyn ProvenanceSigner` works) so a CI
/// step can pick the backend at runtime based on whether
/// `ACTIONS_ID_TOKEN_REQUEST_TOKEN` is set.
pub trait ProvenanceSigner {
    /// Algorithm tag this signer produces. Constant for the lifetime
    /// of the signer.
    fn algorithm(&self) -> SigAlgorithm;

    /// Stable identity placed in the DSSE envelope's `keyid` field.
    /// Verifiers may use this to select a trust policy, but MUST NOT
    /// implicitly trust any key embedded in the envelope itself.
    fn key_id(&self) -> &str;

    /// Sign DSSE PAE bytes. The PAE is constructed by the producer and
    /// passed in opaque; a signer that re-builds the PAE introduces a
    /// drift risk.
    fn sign_pae(&self, pae: &[u8]) -> Result<SignatureMaterial>;
}

// ---------------------------------------------------------------------------
// Ed25519 local signer -- Phase 1.5/1.6 default backend
// ---------------------------------------------------------------------------

/// Ed25519 signer backed by a `KeyPair` whose private key lives in a
/// local file (or in memory after `keygen`). This is the development
/// and current-CI backend; it remains supported indefinitely as the
/// fallback identity model for offline builds and tests.
///
/// Security caveat: the private key bytes pass through this struct in
/// memory. For long-lived production keys, use
/// [`super::cosign_cli::CosignCliKeylessSigner`] (Phase 2.2) so no long-lived key exists in
/// the first place.
#[derive(Debug, Clone)]
pub struct Ed25519LocalSigner {
    keypair: KeyPair,
}

impl Ed25519LocalSigner {
    /// Build a signer from an owned key pair. Use this when the caller
    /// already has the `KeyPair` by value (e.g. just produced by
    /// `generate_keypair()`).
    pub fn new(keypair: KeyPair) -> Self {
        Self { keypair }
    }

    /// Build a signer from a borrowed key pair. Internally clones the
    /// strings, which is cheap (two short base64s + a UUID) and frees
    /// the signer from the caller's lifetime.
    pub fn from_ref(keypair: &KeyPair) -> Self {
        Self {
            keypair: keypair.clone(),
        }
    }

    /// Expose the underlying public key (base64) so callers can record
    /// it alongside the envelope for verification. The Sigstore backend
    /// will expose a cert instead; verifiers select between them based
    /// on whether `SignatureMaterial::cert_chain_pem` is populated.
    pub fn public_key_b64(&self) -> &str {
        &self.keypair.public_key
    }
}

impl ProvenanceSigner for Ed25519LocalSigner {
    fn algorithm(&self) -> SigAlgorithm {
        SigAlgorithm::Ed25519
    }

    fn key_id(&self) -> &str {
        &self.keypair.key_id
    }

    fn sign_pae(&self, pae: &[u8]) -> Result<SignatureMaterial> {
        // `KeyPair::sign` returns a base64 string for legacy reasons
        // (the pre-Phase-1.5 API surface persists across the workspace).
        // We decode it here so the trait contract -- raw bytes only --
        // holds even when the underlying primitive emits base64.
        let sig_b64 = self.keypair.sign(pae)?;
        let bytes = general_purpose::STANDARD
            .decode(&sig_b64)
            .map_err(MkpeError::Base64Error)?;
        // Defensive check: ed25519 signatures are exactly 64 bytes.
        // A length mismatch means the inner KeyPair switched algorithms
        // out from under us, which would be a coordination bug worth
        // failing on rather than papering over.
        if bytes.len() != 64 {
            return Err(MkpeError::DsseError(format!(
                "ed25519 signature length must be 64 bytes; got {}",
                bytes.len()
            )));
        }
        Ok(SignatureMaterial {
            algorithm: SigAlgorithm::Ed25519,
            key_id: self.keypair.key_id.clone(),
            signature: bytes,
            cert_chain_pem: None,
            sigstore_bundle: None,
        })
    }
}

// ---------------------------------------------------------------------------
// KeyPair blanket impl -- preserves Phase 1.6 call-site ergonomics
// ---------------------------------------------------------------------------

/// Blanket implementation so existing code that passes `&KeyPair`
/// continues to compile after the producer migrated to the trait.
/// New code should construct an explicit `Ed25519LocalSigner` to make
/// the algorithm choice readable at the call site.
impl ProvenanceSigner for KeyPair {
    fn algorithm(&self) -> SigAlgorithm {
        SigAlgorithm::Ed25519
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign_pae(&self, pae: &[u8]) -> Result<SignatureMaterial> {
        Ed25519LocalSigner::from_ref(self).sign_pae(pae)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;

    // The signer treats its input as opaque bytes -- PAE shape is a
    // producer concern, not a signer concern -- so these tests sign a
    // fixed byte string rather than building real PAE. That keeps this
    // file independent of `crate::provenance`'s PAE encoding.
    const FAKE_PAE: &[u8] = b"DSSEv1 12 test/payload 5 hello";

    #[test]
    fn ed25519_local_signer_reports_algorithm_and_key_id() {
        let kp = generate_keypair();
        let signer = Ed25519LocalSigner::from_ref(&kp);
        assert_eq!(signer.algorithm(), SigAlgorithm::Ed25519);
        assert_eq!(signer.key_id(), kp.key_id.as_str());
        assert_eq!(signer.public_key_b64(), kp.public_key.as_str());
    }

    #[test]
    fn ed25519_local_signer_produces_64_byte_signature_and_no_cert() {
        let kp = generate_keypair();
        let signer = Ed25519LocalSigner::from_ref(&kp);

        let mat = signer.sign_pae(FAKE_PAE).expect("sign");
        assert_eq!(mat.algorithm, SigAlgorithm::Ed25519);
        assert_eq!(mat.key_id, kp.key_id);
        assert_eq!(mat.signature.len(), 64, "ed25519 sig is always 64 bytes");
        assert!(
            mat.cert_chain_pem.is_none(),
            "local-key signer must never populate cert_chain_pem"
        );
    }

    #[test]
    fn keypair_blanket_impl_matches_explicit_signer() {
        let kp = generate_keypair();
        let via_blanket = kp.sign_pae(FAKE_PAE).expect("blanket sign");
        let via_explicit = Ed25519LocalSigner::from_ref(&kp)
            .sign_pae(FAKE_PAE)
            .expect("explicit sign");

        // Ed25519 is deterministic (RFC 8032): same key + same message
        // MUST yield byte-identical signatures. This is what makes the
        // attestation envelope reproducible for the local-key backend.
        assert_eq!(via_blanket.signature, via_explicit.signature);
        assert_eq!(via_blanket.key_id, via_explicit.key_id);
        assert_eq!(via_blanket.algorithm, via_explicit.algorithm);
    }

    #[test]
    fn dyn_dispatch_works_for_object_safety() {
        // If `ProvenanceSigner` ever loses object-safety the CI code
        // path that picks a backend at runtime (`&dyn ProvenanceSigner`)
        // breaks at compile time. This test exists solely to fail-build
        // on that regression.
        let kp = generate_keypair();
        let signer: &dyn ProvenanceSigner = &kp;
        let _ = signer.algorithm();
        let _ = signer.key_id();
        let mat = signer.sign_pae(FAKE_PAE).expect("dyn sign");
        assert_eq!(mat.signature.len(), 64);
    }

    #[test]
    fn sig_algorithm_wire_tags_are_stable() {
        // These strings appear in logs and in the future DSSE `algorithm`
        // extension. Changing them is a wire-format break -- failing the
        // test here is the right outcome to force a coordinated change.
        assert_eq!(SigAlgorithm::Ed25519.as_str(), "ed25519");
        assert_eq!(SigAlgorithm::EcdsaP256Sha256.as_str(), "ecdsa-p256-sha256");
    }
}
