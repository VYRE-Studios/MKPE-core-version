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

pub mod audit;
pub mod bundle;
pub mod cdna;
pub mod crypto;
pub mod error;
pub mod manifest;
pub mod proof;

pub use audit::{AuditEvent, AuditEventType, AuditLog};
pub use bundle::{create_mkpe_bundle, ArtifactVerificationReport, MkpeArchive};
pub use cdna::{CdnaEdge, CdnaNode, CdnaSchema};
pub use crypto::{generate_keypair, KeyPair};
pub use error::{MkpeError, Result};
pub use manifest::{Manifest, SystemFingerprint};
pub use proof::{
    create_proof_item, verify_proof_bundle, verify_proof_item, ProofBundle, ProofItem,
    SystemFingerprint as ProofSystemFingerprint,
};

/// MKPE version constant
pub const MKPE_VERSION: &str = "1.0.1-mkpe";

/// MKPE schema version
pub const SCHEMA_VERSION: &str = "1.0.0";
