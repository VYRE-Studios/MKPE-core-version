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
pub mod error;
pub mod manifest;
pub mod proof;
pub mod stego;
pub mod timestamp;

pub use attestation::{
    create_build_attestation, hash_subject, verify_build_attestation, AttestationOptions,
    AttestationSubjectKind, AttestationVerificationOptions, AttestationVerificationReport,
    BuildAttestation, BuildFingerprint,
};
pub use audit::{AuditEvent, AuditEventType, AuditLog};
pub use bundle::{
    create_mkpe_bundle, default_sidecar_path, ArtifactVerificationReport, MkpeArchive,
};
pub use stego::{embed_lsb, embed_provenance, extract_lsb, extract_provenance};
pub use timestamp::request_timestamp;
pub use cdna::{CdnaEdge, CdnaNode, CdnaSchema};
pub use crypto::{generate_keypair, KeyPair};
pub use error::{MkpeError, Result};
pub use manifest::{Manifest, SystemFingerprint};
pub use proof::{
    build_merkle_root, create_proof_item, generate_inclusion_proof, verify_inclusion_proof,
    verify_proof_bundle, verify_proof_item, MerkleInclusionProof, ProofBundle, ProofItem,
};

/// MKPE version constant
pub const MKPE_VERSION: &str = "1.1.0-mkpe";

/// MKPE schema version
pub const SCHEMA_VERSION: &str = "1.0.0";
