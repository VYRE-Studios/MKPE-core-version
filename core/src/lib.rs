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

pub mod crypto;
pub mod proof;
pub mod manifest;
pub mod bundle;
pub mod cdna;
pub mod error;
pub mod audit;

pub use error::{MkpeError, Result};
pub use crypto::{KeyPair, generate_keypair};
pub use proof::{ProofItem, ProofBundle, SystemFingerprint as ProofSystemFingerprint, create_proof_item, verify_proof_item, verify_proof_bundle};
pub use manifest::{Manifest, SystemFingerprint};
pub use bundle::{MkpeArchive, create_mkpe_bundle};
pub use cdna::{CdnaSchema, CdnaNode, CdnaEdge};
pub use audit::{AuditLog, AuditEvent, AuditEventType};

/// MKPE version constant
pub const MKPE_VERSION: &str = "1.0.1-mkpe";

/// MKPE schema version
pub const SCHEMA_VERSION: &str = "1.0.0";

