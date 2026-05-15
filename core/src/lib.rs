//! # Morse-Kirby Provenance Engine (MKPE) v1.0.0
//!
//! The canonical provenance engine providing cryptographic verification
//! for creative and computational processes.
//!
//! ## Core Principle
//! "Every verified object carries its own truth."
//!
//! ## Lineage
//! - ADNA (Architectural DNA): Structural mapping
//! - CDNA (Component DNA): Granular component identity  
//! - MKPE: Cryptographic provenance chain
//!
//! ## Features
//! - Ed25519 digital signatures
//! - SHA-256 content hashing
//! - Recursive proof bundling
//! - Self-verifying manifests
//! - .mkpe archive format

pub mod attestation;
pub mod audit;
pub mod bundle;
pub mod cdna;
pub mod crypto;
pub mod dsse;
pub mod error;
pub mod manifest;
pub mod proof;
pub mod multisig;
pub mod policy;
pub mod ownership;
pub mod policy_v2;
pub mod genesis;
pub mod stego;
pub mod timestamp;



// FIXME(slsa-l3-pr): `intoto` and `slsa` modules were declared in commit
// 852ced7 ("policy engine v2") but the corresponding files were never
// committed. Compilation has been broken since. The self-contained
// `provenance` module below provides the SLSA Build Provenance v1.0 +
// in-toto Statement + DSSE envelope implementation those modules were
// presumably meant to host. If the originals are recovered, fold them
// in as a follow-up.
// pub mod intoto;
// pub mod slsa;
pub mod provenance;

pub mod dna;
pub mod format_dna;
	pub use attestation::{
	    create_build_attestation, hash_subject, verify_build_attestation,
	    // FIXME(slsa-l3-pr): `verify_legacy_build_attestation` and
	    // `SlsaProvenanceAttestation` are re-exported here but never defined
	    // in `attestation.rs`. They were planned-but-not-shipped APIs (same
	    // PR landed `pub mod intoto;` / `pub mod slsa;` without the files).
	    // Removed to unbreak the build; restore if the symbols are added.
	    AttestationOptions, AttestationSubjectKind, AttestationVerificationOptions,
	    AttestationVerificationReport, BuildAttestation, BuildFingerprint, BuildInfo,
	    Dependency,
	};
pub use audit::{AuditEvent, AuditEventType, AuditLog};
pub use bundle::{
    create_mkpe_bundle, create_mkpe_bundle_with_ownership, default_sidecar_path,
    ArtifactVerificationReport, MkpeArchive,
};
pub use stego::{embed_lsb, embed_provenance, extract_lsb, extract_provenance};
pub use timestamp::request_timestamp;
pub use dna::{DnaTag, embed_dna, extract_dna, derive_dna_secret, crc64, embed_dna_raw, extract_dna_raw};
pub use format_dna::{
    embed_format_aware, embed_format_aware_with_payload, extract_format_aware,
};
pub use ownership::{
    OwnershipChain, RevocationEntry, SignatureEntry, TransferManifest,
    TransferStatus, TransferTerms,
};
pub use genesis::{GenesisCertificate, GenesisId, GenesisCertificateBuilder, ArtifactDescription, CreatorInfo, ContributorEntry, ContributorRole, VerificationReport};
pub use cdna::{CdnaEdge, CdnaNode, CdnaSchema};
pub use crypto::{
    generate_keypair, generate_software_key, generate_tpm_key, generate_yubikey_key,
    load_signing_key, Algorithm, KeyBackend, KeyPair, Signer, SigningKey,
    TpmSealedKey, YubiKeyHmacKey,
};
pub use dsse::{DSSEEnvelope, DSSSignature, DSSE_PAYLOAD_TYPE};
pub use error::{MkpeError, Result};
	pub use manifest::{Manifest, SystemFingerprint, KeyMetadata, RevocationList};
	pub use policy::{Policy, PolicyCondition, PolicyEngine};
	pub use multisig::{MultiSignature, MultiSignatureManifest, SignatureInfo, verify_multisig};
	pub use proof::{
	    build_merkle_root, create_proof_bundle, create_proof_item, create_recursive_proofs,
	    generate_inclusion_proof, verify_inclusion_proof, verify_proof_bundle,
	    verify_proof_item, MerkleInclusionProof, ProofBundle, ProofItem,
	};

// SLSA / in-toto / DSSE re-exports come from the self-contained `provenance`
// module below. The original `intoto::*` / `slsa::*` re-exports referenced
// modules that were never committed (see FIXME at top of file).
// pub use intoto::{DigestSet, IN_TOTO_STATEMENT_TYPE, Statement, Subject};
// pub use slsa::{BuildDefinition, BuildMetadata, Builder, Byproduct, ProvenancePredicate, ResolvedDependency, RunDetails, SLSA_PROVENANCE_PREDICATE_TYPE};
pub use provenance::{
    Builder as ProvenanceBuilder, BuildDefinition, Byproduct, CrossCompiler, Digest,
    CosignCliKeylessSigner, DsseEnvelope, DsseSignature, Ed25519LocalSigner, ExternalParameters,
    InternalParameters,
    Metadata, ProvenanceSigner, ResolvedDependency, Runner, RustToolchain, RunDetails,
    SigAlgorithm, SignatureMaterial, SlsaProvenance, Statement, StatementBuilder, Subject,
    WorkflowRef, BUILD_TYPE, PAYLOAD_TYPE, PREDICATE_TYPE, STATEMENT_TYPE, SUPPORTED_PROFILES,
    SUPPORTED_TARGETS,
};
pub use provenance::lockfile::{
    apply_git_dep_digests, parse_lockfile, parse_lockfile_str, GitDep, ParsedLockfile,
};
pub use provenance::producer::{
    prepare_attestation,
    produce as produce_attestation,
    produce_with_options as produce_attestation_with_options,
    BuildContext, BuildContextSpec, ProduceOptions, ProducedAttestation,
};

/// MKPE version constant
pub const MKPE_VERSION: &str = "1.2.0-mkpe";

/// MKPE schema version
pub const SCHEMA_VERSION: &str = "1.0.0";