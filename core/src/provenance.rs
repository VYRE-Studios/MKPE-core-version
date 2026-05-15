//! SLSA Build Provenance v1.0 producer and verifier for MKPE.
//!
//! This module emits attestations in the canonical [in-toto Statement v1]
//! format with a [SLSA Provenance v1.0] predicate, wrapped in a [DSSE]
//! envelope for signing. The wire format is interoperable with
//! `slsa-verifier`, `cosign verify-attestation`, and any tool that consumes
//! standard SLSA v1.0 provenance.
//!
//! The JSON Schema for the unsigned Statement lives at
//! `schemas/provenance_v1.schema.json` and is embedded in this crate via
//! `include_str!` so producer and verifier cannot drift.
//!
//! ## Threat model
//!
//! - **Tampered subject digest:** caught by signature verification (the
//!   digest is inside the signed Statement bytes).
//! - **Tampered predicate fields:** same.
//! - **Replayed attestation across subjects:** the verifier MUST check that
//!   the subject digest in the Statement matches the artifact it's
//!   validating; this module surfaces the Statement's subjects so callers
//!   can do that comparison.
//! - **Wrong-key acceptance:** for local ed25519, verification requires the
//!   caller-supplied public key. For Sigstore keyless, trust is established
//!   via `cosign verify-blob` with explicit certificate identity policy; MKPE
//!   does not auto-trust keys from the envelope alone.
//! - **Payload-type confusion:** DSSE PAE includes the `payloadType` in
//!   the signed bytes, so an envelope signed for `application/vnd.in-toto+json`
//!   cannot be silently re-interpreted as a different format.
//!
//! [in-toto Statement v1]: https://in-toto.io/Statement/v1.0
//! [SLSA Provenance v1.0]: https://slsa.dev/spec/v1.0/provenance
//! [DSSE]: https://github.com/secure-systems-lab/dsse

use crate::{crypto::verify_signature, MkpeError, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use jsonschema::JSONSchema;
use serde::{Deserialize, Serialize};

pub mod cosign_cli;
pub mod lockfile;
pub mod producer;
pub mod signing;

pub use cosign_cli::CosignCliKeylessSigner;
pub use signing::{Ed25519LocalSigner, ProvenanceSigner, SigAlgorithm, SignatureMaterial};

// ---------------------------------------------------------------------------
// Stable URIs and constants
// ---------------------------------------------------------------------------

/// The in-toto Statement v1 envelope type. Verifiers reject anything else.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// SLSA Provenance v1.0 predicate type. This is the only predicate type
/// MKPE produces.
pub const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";

/// MKPE's stable buildType URI. Bumping this is a breaking change to
/// every existing verifier; do not bump without a coordinated rollout.
pub const BUILD_TYPE: &str = "https://github.com/VyreVault/mkpe/build/v1";

/// DSSE payloadType for in-toto Statements. Fixed by the in-toto spec.
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// JSON Schema for the Statement, embedded at compile time so a moved or
/// deleted schema file fails the build instead of the runtime.
const SCHEMA_JSON: &str = include_str!("../../schemas/provenance_v1.schema.json");

// ---------------------------------------------------------------------------
// In-toto Statement envelope (unsigned)
// ---------------------------------------------------------------------------

/// The in-toto Statement v1 envelope. Wraps a SLSA Provenance v1.0 predicate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Statement {
    /// Always [`STATEMENT_TYPE`]. The leading underscore is part of the wire
    /// format, not a Rust convention.
    #[serde(rename = "_type")]
    pub type_: String,

    /// Artifacts this attestation makes claims about. Each entry pairs a
    /// human-readable name with content digests.
    pub subject: Vec<Subject>,

    /// Always [`PREDICATE_TYPE`]. Verifiers reject unknown predicate types.
    #[serde(rename = "predicateType")]
    pub predicate_type: String,

    /// The SLSA Provenance v1.0 predicate body.
    pub predicate: SlsaProvenance,
}

/// A single artifact being attested.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    pub digest: Digest,
}

/// Content digests for an artifact. SHA-256 is mandatory; additional
/// algorithms are optional and parallel.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Digest {
    pub sha256: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha512: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake2b: Option<String>,
}

// ---------------------------------------------------------------------------
// SLSA Provenance v1.0 predicate
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlsaProvenance {
    #[serde(rename = "buildDefinition")]
    pub build_definition: BuildDefinition,

    #[serde(rename = "runDetails")]
    pub run_details: RunDetails,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuildDefinition {
    /// Always [`BUILD_TYPE`].
    #[serde(rename = "buildType")]
    pub build_type: String,

    /// Source-controlled inputs.
    #[serde(rename = "externalParameters")]
    pub external_parameters: ExternalParameters,

    /// Builder-controlled inputs (evidence, not user input).
    #[serde(rename = "internalParameters")]
    pub internal_parameters: InternalParameters,

    /// Pinned dependency closure. Mirrors `Cargo.lock`.
    #[serde(rename = "resolvedDependencies")]
    pub resolved_dependencies: Vec<ResolvedDependency>,
}

// `ref` is a Rust keyword, so the field is named `ref_` and re-mapped to
// `"ref"` via manual Serialize/Deserialize below. Derive macros are
// deliberately omitted to avoid a conflicting-impl error.
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalParameters {
    /// Canonical source URI, e.g. `git+https://github.com/VyreVault/mkpe@<sha>`.
    pub source: String,

    /// Git ref being built, e.g. `refs/tags/v1.1.0`.
    pub ref_: String,

    /// Cargo target triple. Validated against [`SUPPORTED_TARGETS`].
    pub target: String,

    /// Cargo profile (`dist` or `release`).
    pub profile: String,

    /// The workflow file's identity at build time.
    pub workflow: WorkflowRef,
}

// Custom Serialize/Deserialize to map `ref_` <-> `"ref"` while keeping the
// rest of the struct derive-friendly. Doing this manually for one field is
// less fragile than serde's `rename` macro chains across nested structs.
impl Serialize for ExternalParameters {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = ser.serialize_struct("ExternalParameters", 5)?;
        s.serialize_field("source", &self.source)?;
        s.serialize_field("ref", &self.ref_)?;
        s.serialize_field("target", &self.target)?;
        s.serialize_field("profile", &self.profile)?;
        s.serialize_field("workflow", &self.workflow)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for ExternalParameters {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            source: String,
            #[serde(rename = "ref")]
            ref_: String,
            target: String,
            profile: String,
            workflow: WorkflowRef,
        }
        let h = Helper::deserialize(de)?;
        Ok(Self {
            source: h.source,
            ref_: h.ref_,
            target: h.target,
            profile: h.profile,
            workflow: h.workflow,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowRef {
    /// Always `.github/workflows/release.yml` per the schema.
    pub path: String,

    /// The workflow file's commit SHA at build time.
    #[serde(rename = "ref")]
    pub ref_: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InternalParameters {
    #[serde(rename = "rustToolchain")]
    pub rust_toolchain: RustToolchain,

    pub runner: Runner,

    /// Present only when cross-compiling Windows artifacts from a Linux
    /// runner via cargo-xwin.
    #[serde(rename = "crossCompiler", default, skip_serializing_if = "Option::is_none")]
    pub cross_compiler: Option<CrossCompiler>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RustToolchain {
    /// Semver patch version, e.g. `1.93.1`.
    pub channel: String,

    /// rustc host triple, e.g. `x86_64-unknown-linux-gnu`.
    pub host: String,

    #[serde(rename = "rustcCommit", default, skip_serializing_if = "Option::is_none")]
    pub rustc_commit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Runner {
    pub os: String,
    pub arch: String,

    /// Pinned runner image, e.g. `ubuntu-24.04@sha256:...`. The trailing
    /// digest is required for SLSA L3 -- a floating image tag breaks
    /// reproducibility.
    pub image: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrossCompiler {
    /// Always `cargo-xwin` for MKPE's pipeline.
    pub tool: String,
    #[serde(rename = "toolVersion")]
    pub tool_version: String,
    #[serde(rename = "msvcSdkSha256")]
    pub msvc_sdk_sha256: String,
    #[serde(rename = "clangVersion")]
    pub clang_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedDependency {
    /// Package URL, e.g. `pkg:cargo/serde@1.0.228`.
    pub uri: String,
    pub digest: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunDetails {
    pub builder: Builder,
    pub metadata: Metadata,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub byproducts: Vec<Byproduct>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Builder {
    /// Globally unique builder identity. The SLSA L3 trust anchor.
    pub id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<std::collections::BTreeMap<String, String>>,

    #[serde(
        rename = "builderDependencies",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub builder_dependencies: Vec<ResolvedDependency>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(rename = "invocationId")]
    pub invocation_id: String,

    #[serde(rename = "startedOn")]
    pub started_on: DateTime<Utc>,

    #[serde(rename = "finishedOn")]
    pub finished_on: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Byproduct {
    /// One of the enum values in the JSON Schema.
    pub name: String,
    pub uri: String,
    pub digest: Digest,
}

// ---------------------------------------------------------------------------
// Whitelists -- enforced both at build-time (via builder validation) and
// at verification time (via JSON Schema). Centralized here so they cannot
// drift between producer and verifier.
// ---------------------------------------------------------------------------

/// Cargo target triples MKPE can attest. Adding a target here also requires
/// updating the JSON Schema enum in `schemas/provenance_v1.schema.json`.
pub const SUPPORTED_TARGETS: &[&str] = &[
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "aarch64-apple-darwin",
];

/// Cargo profiles eligible for release attestation.
pub const SUPPORTED_PROFILES: &[&str] = &["dist", "release"];

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Fluent builder for [`Statement`]. Validates required invariants at
/// `.build()` time so a malformed statement can never escape the producer.
#[derive(Debug, Default)]
pub struct StatementBuilder {
    subjects: Vec<Subject>,
    external: Option<ExternalParameters>,
    internal: Option<InternalParameters>,
    resolved: Vec<ResolvedDependency>,
    builder: Option<Builder>,
    metadata: Option<Metadata>,
    byproducts: Vec<Byproduct>,
}

impl Statement {
    /// Start building a new attestation.
    pub fn builder() -> StatementBuilder {
        StatementBuilder::default()
    }

    /// Encode this Statement as canonical (deterministic) JSON for hashing
    /// or signing. Serde's derive serializes struct fields in declaration
    /// order, which gives us a stable encoding without bringing in a full
    /// JCS implementation. The encoding has no trailing newline.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(MkpeError::JsonError)
    }

    /// Validate this Statement against the embedded JSON Schema. Returns
    /// the list of schema errors if any. Called automatically by `sign()`
    /// and by `DsseEnvelope::verify()`.
    pub fn validate_schema(&self) -> Result<()> {
        let schema_value: serde_json::Value = serde_json::from_str(SCHEMA_JSON)
            .map_err(|e| MkpeError::SchemaValidation(format!("invalid embedded schema: {e}")))?;

        // jsonschema 0.18 auto-detects the draft from the schema's `$schema`
        // field. Our schema declares draft 2020-12 explicitly, so we don't
        // need to force a draft here.
        let compiled = JSONSchema::compile(&schema_value)
            .map_err(|e| MkpeError::SchemaValidation(format!("schema compile failed: {e}")))?;

        let instance: serde_json::Value =
            serde_json::to_value(self).map_err(MkpeError::JsonError)?;

        if let Err(errors) = compiled.validate(&instance) {
            let msgs: Vec<String> = errors
                .map(|e| format!("{} at {}", e, e.instance_path))
                .collect();
            return Err(MkpeError::SchemaValidation(msgs.join("; ")));
        }
        Ok(())
    }

    /// Sign this Statement and produce a DSSE envelope ready to publish.
    /// Schema validation runs first; a statement that fails validation
    /// cannot be signed.
    ///
    /// The signer is anything that implements [`ProvenanceSigner`] -- a
    /// `&KeyPair` for the Phase 1.6 local-file path, a future
    /// `SigstoreKeylessSigner` for SLSA L3 builds. The DSSE envelope
    /// shape is identical across backends; what differs is whether the
    /// signature's `cert` field is populated.
    pub fn sign<S: ProvenanceSigner + ?Sized>(&self, signer: &S) -> Result<DsseEnvelope> {
        self.validate_schema()?;
        let payload = self.to_canonical_json()?;
        let pae = dsse_pae(PAYLOAD_TYPE.as_bytes(), &payload);
        let mat = signer.sign_pae(&pae)?;
        Ok(DsseEnvelope {
            payload: general_purpose::STANDARD.encode(&payload),
            payload_type: PAYLOAD_TYPE.to_string(),
            signatures: vec![DsseSignature {
                keyid: mat.key_id,
                sig: general_purpose::STANDARD.encode(&mat.signature),
                cert: mat.cert_chain_pem,
                sigstore_bundle: mat.sigstore_bundle.clone(),
            }],
        })
    }
}

impl StatementBuilder {
    /// Add an artifact this attestation covers. Must be called at least
    /// once before `build()`.
    pub fn subject(mut self, name: impl Into<String>, sha256: impl Into<String>) -> Self {
        self.subjects.push(Subject {
            name: name.into(),
            digest: Digest {
                sha256: sha256.into(),
                ..Default::default()
            },
        });
        self
    }

    pub fn external_parameters(mut self, p: ExternalParameters) -> Self {
        self.external = Some(p);
        self
    }

    pub fn internal_parameters(mut self, p: InternalParameters) -> Self {
        self.internal = Some(p);
        self
    }

    pub fn resolved_dependencies(mut self, deps: Vec<ResolvedDependency>) -> Self {
        self.resolved = deps;
        self
    }

    pub fn builder_identity(mut self, b: Builder) -> Self {
        self.builder = Some(b);
        self
    }

    pub fn metadata(mut self, m: Metadata) -> Self {
        self.metadata = Some(m);
        self
    }

    pub fn byproducts(mut self, b: Vec<Byproduct>) -> Self {
        self.byproducts = b;
        self
    }

    /// Finalize the Statement. Errors if any required field is missing or
    /// if any value violates an MKPE invariant (unsupported target, unknown
    /// profile, malformed digest).
    pub fn build(self) -> Result<Statement> {
        let external = self
            .external
            .ok_or_else(|| MkpeError::ProvenanceError("externalParameters not set".into()))?;
        let internal = self
            .internal
            .ok_or_else(|| MkpeError::ProvenanceError("internalParameters not set".into()))?;
        let builder = self
            .builder
            .ok_or_else(|| MkpeError::ProvenanceError("builder identity not set".into()))?;
        let metadata = self
            .metadata
            .ok_or_else(|| MkpeError::ProvenanceError("metadata not set".into()))?;

        if self.subjects.is_empty() {
            return Err(MkpeError::ProvenanceError(
                "at least one subject is required".into(),
            ));
        }
        for s in &self.subjects {
            if s.digest.sha256.len() != 64 || !s.digest.sha256.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(MkpeError::ProvenanceError(format!(
                    "subject {:?}: sha256 must be 64 lowercase hex chars",
                    s.name
                )));
            }
            if s.digest.sha256 != s.digest.sha256.to_lowercase() {
                return Err(MkpeError::ProvenanceError(format!(
                    "subject {:?}: sha256 must be lowercase",
                    s.name
                )));
            }
        }
        if !SUPPORTED_TARGETS.contains(&external.target.as_str()) {
            return Err(MkpeError::ProvenanceError(format!(
                "unsupported target {:?}; allowed: {:?}",
                external.target, SUPPORTED_TARGETS
            )));
        }
        if !SUPPORTED_PROFILES.contains(&external.profile.as_str()) {
            return Err(MkpeError::ProvenanceError(format!(
                "unsupported profile {:?}; allowed: {:?}",
                external.profile, SUPPORTED_PROFILES
            )));
        }
        if metadata.finished_on < metadata.started_on {
            return Err(MkpeError::ProvenanceError(
                "metadata.finishedOn precedes startedOn".into(),
            ));
        }

        let stmt = Statement {
            type_: STATEMENT_TYPE.to_string(),
            subject: self.subjects,
            predicate_type: PREDICATE_TYPE.to_string(),
            predicate: SlsaProvenance {
                build_definition: BuildDefinition {
                    build_type: BUILD_TYPE.to_string(),
                    external_parameters: external,
                    internal_parameters: internal,
                    resolved_dependencies: self.resolved,
                },
                run_details: RunDetails {
                    builder,
                    metadata,
                    byproducts: self.byproducts,
                },
            },
        };
        Ok(stmt)
    }
}

// ---------------------------------------------------------------------------
// DSSE envelope
// ---------------------------------------------------------------------------

/// DSSE-wrapped Statement, ready to publish alongside the artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DsseEnvelope {
    /// Base64-encoded Statement JSON.
    pub payload: String,

    /// Always [`PAYLOAD_TYPE`].
    #[serde(rename = "payloadType")]
    pub payload_type: String,

    /// One signature per signer. A single ed25519 signer is the common case.
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DsseSignature {
    /// Opaque key identifier. For Sigstore-keyless this is the OIDC
    /// subject URI of the workflow identity; for our own ed25519 keys
    /// this is `KeyPair::key_id` (a UUID).
    pub keyid: String,
    /// Base64-encoded raw signature bytes (encoded exactly once, by
    /// `Statement::sign`).
    pub sig: String,
    /// Sigstore Cosign Bundle compatibility field: PEM-encoded Fulcio
    /// leaf-and-intermediates cert chain. `None` for local-key
    /// signatures (Phase 1.5/1.6 backend) and KMS signatures.
    /// `skip_serializing_if = "Option::is_none"` keeps the on-wire
    /// shape backward-compatible with envelopes issued before Phase 2.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    /// Full Sigstore bundle from `cosign sign-blob --bundle`. When present,
    /// verification uses `cosign verify-blob` instead of ed25519 pubkey.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sigstore_bundle: Option<serde_json::Value>,
}

impl DsseEnvelope {
    /// Decode the embedded Statement bytes and parse them. Note: this does
    /// NOT verify the signature -- use [`verify`] or [`verify_any`] for that.
    pub fn decode_payload(&self) -> Result<Statement> {
        let bytes = general_purpose::STANDARD
            .decode(&self.payload)
            .map_err(MkpeError::Base64Error)?;
        serde_json::from_slice(&bytes).map_err(MkpeError::JsonError)
    }

    /// Verify the envelope against a specific expected public key (base64).
    /// On success returns the decoded Statement. On failure, the caller gets
    /// a structured error explaining which check failed.
    ///
    /// Verification steps, in order:
    ///   1. `payloadType` must equal [`PAYLOAD_TYPE`].
    ///   2. At least one signature must verify against `expected_pubkey_b64`
    ///      over the DSSE PAE of the decoded payload.
    ///   3. The decoded Statement must validate against the embedded schema.
    ///
    /// Steps 1 and 2 prevent the attacker from substituting either the
    /// payload type or the payload bytes. Step 3 prevents a downgrade to a
    /// malformed Statement that signature verification alone wouldn't catch.
    ///
    /// Envelopes produced with [`CosignCliKeylessSigner`] embed a Sigstore
    /// bundle and **cannot** be verified with this method; use
    /// [`Self::verify_cosign_keyless`] instead.
    pub fn verify(&self, expected_pubkey_b64: &str) -> Result<Statement> {
        if self.signatures.iter().any(|s| s.sigstore_bundle.is_some()) {
            return Err(MkpeError::DsseError(
                "envelope contains a Sigstore bundle; use DsseEnvelope::verify_cosign_keyless \
                 or `mkpe verify-attestation --certificate-identity ... --certificate-oidc-issuer ...`"
                    .into(),
            ));
        }
        self.verify_ed25519_pubkey(expected_pubkey_b64)
    }

    /// Verify a Sigstore keyless envelope by delegating to `cosign verify-blob`.
    /// The first signature must carry [`DsseSignature::sigstore_bundle`].
    pub fn verify_cosign_keyless(
        &self,
        certificate_identity: &str,
        certificate_oidc_issuer: &str,
    ) -> Result<Statement> {
        if self.payload_type != PAYLOAD_TYPE {
            return Err(MkpeError::DsseError(format!(
                "unexpected payloadType {:?}; expected {:?}",
                self.payload_type, PAYLOAD_TYPE
            )));
        }
        if self.signatures.is_empty() {
            return Err(MkpeError::DsseError("envelope has no signatures".into()));
        }
        let bundle = self.signatures[0].sigstore_bundle.as_ref().ok_or_else(|| {
            MkpeError::DsseError(
                "verify_cosign_keyless requires sigstore_bundle on the first signature".into(),
            )
        })?;

        let payload_bytes = general_purpose::STANDARD
            .decode(&self.payload)
            .map_err(MkpeError::Base64Error)?;
        let pae = dsse_pae(self.payload_type.as_bytes(), &payload_bytes);

        cosign_cli::verify_blob_with_cosign(
            &pae,
            bundle,
            certificate_identity,
            certificate_oidc_issuer,
        )?;

        let statement: Statement = serde_json::from_slice(&payload_bytes).map_err(MkpeError::JsonError)?;
        statement.validate_schema()?;
        Ok(statement)
    }

    fn verify_ed25519_pubkey(&self, expected_pubkey_b64: &str) -> Result<Statement> {
        if self.payload_type != PAYLOAD_TYPE {
            return Err(MkpeError::DsseError(format!(
                "unexpected payloadType {:?}; expected {:?}",
                self.payload_type, PAYLOAD_TYPE
            )));
        }
        if self.signatures.is_empty() {
            return Err(MkpeError::DsseError("envelope has no signatures".into()));
        }

        let payload_bytes = general_purpose::STANDARD
            .decode(&self.payload)
            .map_err(MkpeError::Base64Error)?;
        let pae = dsse_pae(self.payload_type.as_bytes(), &payload_bytes);

        let mut any_valid = false;
        let mut last_error: Option<String> = None;
        for sig in &self.signatures {
            match verify_signature(expected_pubkey_b64, &pae, &sig.sig) {
                Ok(true) => {
                    any_valid = true;
                    break;
                }
                Ok(false) => {
                    last_error = Some(format!("signature by keyid {:?} did not verify", sig.keyid));
                }
                Err(e) => {
                    last_error = Some(format!(
                        "signature by keyid {:?} could not be checked: {e}",
                        sig.keyid
                    ));
                }
            }
        }
        if !any_valid {
            return Err(MkpeError::VerificationFailed(
                last_error.unwrap_or_else(|| "no signature verified".into()),
            ));
        }

        let statement: Statement = serde_json::from_slice(&payload_bytes).map_err(MkpeError::JsonError)?;
        statement.validate_schema()?;
        Ok(statement)
    }
}

// ---------------------------------------------------------------------------
// DSSE PAE (Pre-Authentication Encoding)
//
// PAE(type, payload) = "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload
//
// LEN is ASCII decimal of the byte length. The signed bytes are PAE, NOT
// the raw payload; this prevents payload-type confusion attacks.
// Reference: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
// ---------------------------------------------------------------------------

fn dsse_pae(payload_type: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type);
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;
    use std::collections::BTreeMap;

    /// Build a fully-populated valid Statement for tests.
    fn sample_statement() -> Statement {
        let started: DateTime<Utc> = "2026-06-01T12:00:00Z".parse().unwrap();
        let finished: DateTime<Utc> = "2026-06-01T12:14:23Z".parse().unwrap();
        Statement::builder()
            .subject(
                "mkpe-1.1.0-x86_64-pc-windows-msvc.zip",
                "a".repeat(64),
            )
            .external_parameters(ExternalParameters {
                source: "git+https://github.com/VyreVault/mkpe@1111111111111111111111111111111111111111".into(),
                ref_: "refs/tags/v1.1.0".into(),
                target: "x86_64-pc-windows-msvc".into(),
                profile: "dist".into(),
                workflow: WorkflowRef {
                    path: ".github/workflows/release.yml".into(),
                    ref_: "2".repeat(40),
                },
            })
            .internal_parameters(InternalParameters {
                rust_toolchain: RustToolchain {
                    channel: "1.93.1".into(),
                    host: "x86_64-unknown-linux-gnu".into(),
                    rustc_commit: Some("3".repeat(40)),
                },
                runner: Runner {
                    os: "ubuntu-24.04".into(),
                    arch: "x86_64".into(),
                    image: format!("ghcr.io/actions/runner-images/ubuntu-24.04@sha256:{}", "4".repeat(64)),
                },
                cross_compiler: Some(CrossCompiler {
                    tool: "cargo-xwin".into(),
                    tool_version: "0.18.0".into(),
                    msvc_sdk_sha256: "5".repeat(64),
                    clang_version: "18.1.8".into(),
                }),
            })
            .resolved_dependencies(vec![])
            .builder_identity(Builder {
                id: "https://github.com/VyreVault/mkpe/.github/workflows/release.yml@refs/tags/v1.1.0".into(),
                version: Some({
                    let mut v = BTreeMap::new();
                    v.insert("cargo".into(), "1.93.1".into());
                    v
                }),
                builder_dependencies: vec![],
            })
            .metadata(Metadata {
                invocation_id: "https://github.com/VyreVault/mkpe/actions/runs/99999999".into(),
                started_on: started,
                finished_on: finished,
            })
            .build()
            .expect("sample should build")
    }

    #[test]
    fn round_trip_serialize_deserialize() {
        let s = sample_statement();
        let json = serde_json::to_string(&s).unwrap();
        let parsed: Statement = serde_json::from_str(&json).unwrap();
        assert_eq!(s, parsed, "round-trip must be lossless");
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let s = sample_statement();
        let a = s.to_canonical_json().unwrap();
        let b = s.to_canonical_json().unwrap();
        assert_eq!(a, b, "canonical encoding must be byte-stable");
    }

    #[test]
    fn matches_committed_json_schema() {
        let s = sample_statement();
        s.validate_schema().expect("sample must satisfy schema");
    }

    #[test]
    fn unsupported_target_is_rejected_at_build() {
        let started: DateTime<Utc> = "2026-06-01T12:00:00Z".parse().unwrap();
        let finished = started;
        let err = Statement::builder()
            .subject("mkpe.zip", "a".repeat(64))
            .external_parameters(ExternalParameters {
                source: "git+https://example/mkpe@aaaa".into(),
                ref_: "refs/tags/v1.0.0".into(),
                target: "wasm32-unknown-unknown".into(), // not in whitelist
                profile: "dist".into(),
                workflow: WorkflowRef {
                    path: ".github/workflows/release.yml".into(),
                    ref_: "2".repeat(40),
                },
            })
            .internal_parameters(InternalParameters {
                rust_toolchain: RustToolchain {
                    channel: "1.93.1".into(),
                    host: "x86_64-unknown-linux-gnu".into(),
                    rustc_commit: None,
                },
                runner: Runner {
                    os: "ubuntu-24.04".into(),
                    arch: "x86_64".into(),
                    image: format!("ubuntu@sha256:{}", "4".repeat(64)),
                },
                cross_compiler: None,
            })
            .builder_identity(Builder {
                id: "https://example/builder".into(),
                version: None,
                builder_dependencies: vec![],
            })
            .metadata(Metadata {
                invocation_id: "https://example/run".into(),
                started_on: started,
                finished_on: finished,
            })
            .build()
            .unwrap_err();
        assert!(format!("{err}").contains("unsupported target"));
    }

    #[test]
    fn malformed_subject_digest_is_rejected() {
        let started: DateTime<Utc> = "2026-06-01T12:00:00Z".parse().unwrap();
        let err = Statement::builder()
            .subject("mkpe.zip", "not-a-real-hex-digest")
            .external_parameters(ExternalParameters {
                source: "git+https://example/mkpe@aaaa".into(),
                ref_: "refs/tags/v1.0.0".into(),
                target: "x86_64-pc-windows-msvc".into(),
                profile: "dist".into(),
                workflow: WorkflowRef {
                    path: ".github/workflows/release.yml".into(),
                    ref_: "2".repeat(40),
                },
            })
            .internal_parameters(InternalParameters {
                rust_toolchain: RustToolchain {
                    channel: "1.93.1".into(),
                    host: "x86_64-unknown-linux-gnu".into(),
                    rustc_commit: None,
                },
                runner: Runner {
                    os: "ubuntu-24.04".into(),
                    arch: "x86_64".into(),
                    image: format!("ubuntu@sha256:{}", "4".repeat(64)),
                },
                cross_compiler: None,
            })
            .builder_identity(Builder {
                id: "https://example/builder".into(),
                version: None,
                builder_dependencies: vec![],
            })
            .metadata(Metadata {
                invocation_id: "https://example/run".into(),
                started_on: started,
                finished_on: started,
            })
            .build()
            .unwrap_err();
        assert!(format!("{err}").contains("64 lowercase hex"));
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let stmt = sample_statement();
        let key = generate_keypair();
        let envelope = stmt.sign(&key).expect("sign");
        let verified = envelope
            .verify(&key.public_key)
            .expect("verify with same key must succeed");
        assert_eq!(stmt, verified, "verified statement must equal the signed one");
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let stmt = sample_statement();
        let signer = generate_keypair();
        let other = generate_keypair();
        let envelope = stmt.sign(&signer).expect("sign");
        let err = envelope
            .verify(&other.public_key)
            .expect_err("must reject wrong key");
        assert!(
            matches!(err, MkpeError::VerificationFailed(_)),
            "expected VerificationFailed, got: {err:?}"
        );
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let stmt = sample_statement();
        let key = generate_keypair();
        let mut envelope = stmt.sign(&key).expect("sign");

        // Tamper: swap a single byte in the base64 payload. Decode -> mutate
        // -> re-encode so the tamper still produces a valid base64 string.
        let mut bytes = general_purpose::STANDARD
            .decode(&envelope.payload)
            .unwrap();
        // Flip the last byte of the JSON (likely the closing brace -> something else).
        let idx = bytes.len() - 1;
        bytes[idx] ^= 0x01;
        envelope.payload = general_purpose::STANDARD.encode(&bytes);

        let err = envelope
            .verify(&key.public_key)
            .expect_err("tampered payload must not verify");
        // Either the signature won't verify or the now-invalid JSON fails parse.
        assert!(
            matches!(
                err,
                MkpeError::VerificationFailed(_) | MkpeError::JsonError(_) | MkpeError::SchemaValidation(_)
            ),
            "unexpected error variant: {err:?}"
        );
    }

    #[test]
    fn tampered_payload_type_fails_verification() {
        let stmt = sample_statement();
        let key = generate_keypair();
        let mut envelope = stmt.sign(&key).expect("sign");
        envelope.payload_type = "application/vnd.attacker+json".into();
        let err = envelope
            .verify(&key.public_key)
            .expect_err("wrong payloadType must be rejected");
        assert!(matches!(err, MkpeError::DsseError(_)));
    }

    #[test]
    fn dsse_pae_matches_spec_example() {
        // From DSSE protocol.md example:
        //   type = "http://example.com/HelloWorld"
        //   payload = "hello world"
        // PAE = b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        let pae = dsse_pae(b"http://example.com/HelloWorld", b"hello world");
        assert_eq!(
            pae,
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec(),
            "PAE encoding must match DSSE v1 spec example byte-for-byte"
        );
    }

    #[test]
    fn verify_rejects_pubkey_when_sigstore_bundle_present() {
        let stmt = sample_statement();
        let key = generate_keypair();
        let mut envelope = stmt.sign(&key).expect("sign");
        envelope.signatures[0].sigstore_bundle = Some(serde_json::json!({}));
        let err = envelope
            .verify(&key.public_key)
            .expect_err("must not use ed25519 path");
        assert!(matches!(err, MkpeError::DsseError(_)));
    }

    #[test]
    fn unknown_payload_type_in_envelope_is_rejected() {
        let env = DsseEnvelope {
            payload: general_purpose::STANDARD.encode(b"{}"),
            payload_type: "application/json".into(),
            signatures: vec![DsseSignature {
                keyid: "x".into(),
                sig: "x".into(),
                cert: None,
                sigstore_bundle: None,
            }],
        };
        let err = env.verify("AAAA").expect_err("must reject");
        assert!(matches!(err, MkpeError::DsseError(_)));
    }

    #[test]
    fn empty_signatures_array_is_rejected() {
        let env = DsseEnvelope {
            payload: general_purpose::STANDARD.encode(b"{}"),
            payload_type: PAYLOAD_TYPE.into(),
            signatures: vec![],
        };
        let err = env.verify("AAAA").expect_err("must reject");
        assert!(matches!(err, MkpeError::DsseError(_)));
    }
}
