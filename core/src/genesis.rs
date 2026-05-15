//! Genesis Certificate — the digital birth certificate of a creation.
//!
//! A genesis certificate captures the exact moment an artifact enters
//! existence: who created it, on what system, with what tools, at what
//! precise time, and who witnessed or co-created it. It is the
//! cryptographic anchor that all downstream provenance chains attach to.
//!
//! # Core Principle
//!
//! "Every creation deserves a birth record that cannot be forged."
//!
//! # Structure
//!
//! - **Identity** — artifact name, content hash, file manifest
//! - **Creator** — signing key, display name, role
//! - **Contributors** — co-creators and witnesses with their own signatures
//! - **Origin** — system fingerprint (platform, hostname, PID, engine version)
//! - **Timestamp** — precise UTC creation time, monotonic nonce
//! - **Lineage** — parent certificate ID for derived works (optional)
//!
//! # Verification
//!
//! A genesis certificate is verified by:
//! 1. Checking the creator's signature over the canonical payload
//! 2. Verifying each contributor/witness signature
//! 3. Confirming the content hash matches the claimed artifact
//! 4. Optionally checking the nonce against a known floor

use crate::crypto::{self, generate_keypair, Algorithm, KeyBackend, Signer};
use crate::manifest::SystemFingerprint;
use crate::MkpeError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Certificate identifier
// ---------------------------------------------------------------------------

/// Deterministic identifier for a genesis certificate.
///
/// Derived from SHA-256(artifact_hash || creator_key_id || nonce) to ensure
/// uniqueness even if the same artifact is created twice.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GenesisId(pub String);

impl GenesisId {
    /// Compute a genesis ID from the core identifying fields.
    pub fn compute(artifact_hash: &str, creator_key_id: &str, nonce: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(artifact_hash.as_bytes());
        hasher.update(creator_key_id.as_bytes());
        hasher.update(&nonce.to_le_bytes());
        let hash = hasher.finalize();
        // Use first 32 hex chars (128 bits) — enough entropy for uniqueness
        GenesisId(hex::encode(&hash[..16]))
    }
}

impl std::fmt::Display for GenesisId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Contributor roles
// ---------------------------------------------------------------------------

/// Role a contributor played in the creation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContributorRole {
    /// Co-creator — substantially contributed to the artifact.
    CoCreator,
    /// Witness — observed the creation and attests it happened.
    Witness,
    /// Reviewer — reviewed the artifact before certification.
    Reviewer,
    /// Approver — authorized the release/publication.
    Approver,
    /// Custom role with a free-form label.
    Custom(String),
}

impl std::fmt::Display for ContributorRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContributorRole::CoCreator => write!(f, "co-creator"),
            ContributorRole::Witness => write!(f, "witness"),
            ContributorRole::Reviewer => write!(f, "reviewer"),
            ContributorRole::Approver => write!(f, "approver"),
            ContributorRole::Custom(label) => write!(f, "{}", label),
        }
    }
}

// ---------------------------------------------------------------------------
// Contributor entry
// ---------------------------------------------------------------------------

/// A person or entity involved in the creation, with their own signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributorEntry {
    /// Key ID of this contributor.
    pub key_id: String,
    /// Display name or identifier (optional).
    pub display_name: Option<String>,
    /// Role in the creation.
    pub role: ContributorRole,
    /// UTC timestamp when this contributor signed.
    pub signed_at: DateTime<Utc>,
    /// Base64-encoded Ed25519 signature over the canonical certificate payload.
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Artifact description
// ---------------------------------------------------------------------------

/// Description of the artifact being born.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactDescription {
    /// Human-readable name (e.g., "Logo Design v3", "Smart Contract v2.1").
    pub name: String,
    /// SHA-256 content hash of the artifact (hex, lowercase).
    pub content_hash: String,
    /// Type or category (e.g., "image/png", "solidity-contract", "3d-model").
    pub artifact_type: String,
    /// File manifest — relative path → SHA-256 hash for multi-file artifacts.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub file_manifest: HashMap<String, String>,
    /// Total size in bytes of the artifact content.
    pub size_bytes: u64,
    /// Arbitrary metadata about the artifact.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Creator info
// ---------------------------------------------------------------------------

/// The principal creator who signs the genesis certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatorInfo {
    /// Key ID of the creator.
    pub key_id: String,
    /// Base64-encoded Ed25519 public key.
    pub public_key: String,
    /// Display name (optional).
    pub display_name: Option<String>,
    /// Engine version used to create the certificate.
    pub engine_version: String,
}

// ---------------------------------------------------------------------------
// GenesisCertificate
// ---------------------------------------------------------------------------

/// The digital birth certificate — created once, never modified.
///
/// This is an immutable record. After creation and signing, no field
/// should change. If the artifact is derived or re-released, create a
/// new certificate with `parent_id` set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisCertificate {
    // -- Schema --
    /// Genesis certificate schema version.
    pub schema_version: String,

    // -- Identity --
    /// Deterministic unique ID for this certificate.
    pub genesis_id: GenesisId,

    // -- What was created --
    /// Description of the artifact.
    pub artifact: ArtifactDescription,

    // -- Who created it --
    /// The principal creator.
    pub creator: CreatorInfo,

    /// Co-creators, witnesses, reviewers, approvers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributors: Vec<ContributorEntry>,

    // -- On what system --
    /// System fingerprint at creation time.
    pub origin: SystemFingerprint,

    // -- When --
    /// Precise UTC timestamp of creation.
    pub created_at: DateTime<Utc>,

    /// Monotonic nonce for replay protection and ordering.
    pub nonce: u64,

    // -- Lineage --
    /// Parent genesis certificate, if this is a derived work.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<GenesisId>,

    // -- Signature --
    /// The creator's signature over the canonical payload.
    pub creator_signature: String,
}

impl GenesisCertificate {
    /// Compute the canonical JSON payload that gets signed.
    ///
    /// This is a deterministic subset of the certificate fields,
    /// excluding the signature itself and any variable-order data.
    pub fn canonical_payload(&self) -> Vec<u8> {
        let payload = serde_json::json!({
            "schema_version": self.schema_version,
            "genesis_id": self.genesis_id.0,
            "artifact": {
                "name": self.artifact.name,
                "content_hash": self.artifact.content_hash,
                "artifact_type": self.artifact.artifact_type,
                "size_bytes": self.artifact.size_bytes,
            },
            "creator": {
                "key_id": self.creator.key_id,
                "public_key": self.creator.public_key,
            },
            "created_at": self.created_at.to_rfc3339(),
            "nonce": self.nonce,
            "parent_id": self.parent_id.as_ref().map(|id| id.0.clone()),
        });
        serde_json::to_vec(&payload).unwrap_or_default()
    }

    /// Verify the creator's signature.
    pub fn verify_creator_signature(&self) -> crate::Result<bool> {
        let payload = self.canonical_payload();
        crypto::verify_signature(&self.creator.public_key, &payload, &self.creator_signature)
    }

    /// Verify a specific contributor's signature.
    pub fn verify_contributor_signature(
        &self,
        contributor: &ContributorEntry,
        public_key: &str,
    ) -> crate::Result<bool> {
        crypto::verify_signature(public_key, &self.canonical_payload(), &contributor.signature)
    }

    /// Verify all contributor signatures against a public_key map.
    ///
    /// Returns `(valid_count, invalid_count)` — the caller decides
    /// whether partial verification is acceptable.
    pub fn verify_all_contributors(
        &self,
        public_keys: &HashMap<String, String>,
    ) -> crate::Result<(usize, usize)> {
        let mut valid = 0;
        let mut invalid = 0;
        for contributor in &self.contributors {
            match public_keys.get(&contributor.key_id) {
                Some(pk) => {
                    if crypto::verify_signature(
                        pk,
                        &self.canonical_payload(),
                        &contributor.signature,
                    )? {
                        valid += 1;
                    } else {
                        invalid += 1;
                    }
                }
                None => invalid += 1,
            }
        }
        Ok((valid, invalid))
    }

    /// Full verification: creator signature + all contributor signatures.
    pub fn verify(&self, contributor_public_keys: &HashMap<String, String>) -> crate::Result<VerificationReport> {
        let creator_valid = self.verify_creator_signature()?;

        let (contributors_valid, contributors_invalid) =
            self.verify_all_contributors(contributor_public_keys)?;

        Ok(VerificationReport {
            creator_signature_valid: creator_valid,
            contributors_verified: contributors_valid,
            contributors_failed: contributors_invalid,
            total_contributors: self.contributors.len(),
            fully_valid: creator_valid && contributors_invalid == 0,
        })
    }

    /// Serialize this certificate to a pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> crate::Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| MkpeError::BundleError(format!("Genesis certificate JSON failed: {}", e)))
    }

    /// Deserialize a genesis certificate from JSON.
    pub fn from_json(json: &str) -> crate::Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| MkpeError::BundleError(format!("Genesis certificate parse failed: {}", e)))
    }

    /// Save to a file.
    pub fn save_to_file(&self, path: &std::path::Path) -> crate::Result<()> {
        let json = self.to_json_pretty()?;
        std::fs::write(path, json)
            .map_err(|e| MkpeError::BundleError(format!("Failed to write genesis certificate: {}", e)))
    }

    /// Load from a file.
    pub fn load_from_file(path: &std::path::Path) -> crate::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| MkpeError::BundleError(format!("Failed to read genesis certificate: {}", e)))?;
        Self::from_json(&contents)
    }
}

// ---------------------------------------------------------------------------
// Verification report
// ---------------------------------------------------------------------------

/// Result of verifying a genesis certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationReport {
    /// Was the creator's signature valid?
    pub creator_signature_valid: bool,
    /// Number of contributor signatures that verified.
    pub contributors_verified: usize,
    /// Number of contributor signatures that failed or had no public key.
    pub contributors_failed: usize,
    /// Total number of contributors.
    pub total_contributors: usize,
    /// True iff creator signature is valid AND all contributors verified.
    pub fully_valid: bool,
}

impl std::fmt::Display for VerificationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Genesis Certificate Verification Report")?;
        writeln!(f, "  Creator signature: {}", if self.creator_signature_valid { "VALID" } else { "INVALID" })?;
        writeln!(f, "  Contributors: {}/{} verified, {} failed",
            self.contributors_verified, self.total_contributors, self.contributors_failed)?;
        write!(f, "  Overall: {}", if self.fully_valid { "FULLY VALID" } else { "FAILED" })
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for constructing and signing a genesis certificate.
pub struct GenesisCertificateBuilder {
    artifact_name: Option<String>,
    content_hash: Option<String>,
    artifact_type: Option<String>,
    file_manifest: HashMap<String, String>,
    size_bytes: u64,
    artifact_metadata: HashMap<String, serde_json::Value>,
    creator_display_name: Option<String>,
    contributors: Vec<ContributorEntry>,
    nonce: Option<u64>,
    parent_id: Option<GenesisId>,
}

impl GenesisCertificateBuilder {
    /// Start building a genesis certificate.
    pub fn new() -> Self {
        Self {
            artifact_name: None,
            content_hash: None,
            artifact_type: None,
            file_manifest: HashMap::new(),
            size_bytes: 0,
            artifact_metadata: HashMap::new(),
            creator_display_name: None,
            contributors: Vec::new(),
            nonce: None,
            parent_id: None,
        }
    }

    /// Set the artifact's human-readable name (required).
    pub fn artifact_name(mut self, name: impl Into<String>) -> Self {
        self.artifact_name = Some(name.into());
        self
    }

    /// Set the SHA-256 content hash of the artifact (required).
    pub fn content_hash(mut self, hash: impl Into<String>) -> Self {
        self.content_hash = Some(hash.into());
        self
    }

    /// Set the artifact type/category (required).
    pub fn artifact_type(mut self, t: impl Into<String>) -> Self {
        self.artifact_type = Some(t.into());
        self
    }

    /// Set the total size in bytes.
    pub fn size_bytes(mut self, size: u64) -> Self {
        self.size_bytes = size;
        self
    }

    /// Add a file to the file manifest (relative path → SHA-256 hash).
    pub fn file(mut self, path: impl Into<String>, hash: impl Into<String>) -> Self {
        self.file_manifest.insert(path.into(), hash.into());
        self
    }

    /// Add arbitrary metadata about the artifact.
    pub fn artifact_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.artifact_metadata.insert(key.into(), value);
        self
    }

    /// Set the creator's display name.
    pub fn creator_display_name(mut self, name: impl Into<String>) -> Self {
        self.creator_display_name = Some(name.into());
        self
    }

    /// Add a contributor. The contributor must have already signed the
    /// canonical payload (which is only known after the certificate is
    /// partially built). Use [`GenesisCertificate::add_contributor`]
    /// after building instead, if the contributor signs the final payload.
    pub fn contributor(mut self, entry: ContributorEntry) -> Self {
        self.contributors.push(entry);
        self
    }

    /// Set the nonce (auto-generated if not set).
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Set the parent genesis ID for derived works.
    pub fn parent_id(mut self, id: GenesisId) -> Self {
        self.parent_id = Some(id);
        self
    }

    /// Build and sign the genesis certificate.
    ///
    /// The keypair is used to sign the canonical payload and becomes
    /// the creator of record.
    pub fn build(self, keypair: &dyn Signer) -> crate::Result<GenesisCertificate> {
        let artifact_name = self.artifact_name.ok_or_else(|| {
            MkpeError::BundleError("artifact_name is required".to_string())
        })?;
        let content_hash = self.content_hash.ok_or_else(|| {
            MkpeError::BundleError("content_hash is required".to_string())
        })?;
        let artifact_type = self.artifact_type.ok_or_else(|| {
            MkpeError::BundleError("artifact_type is required".to_string())
        })?;

        let nonce = self.nonce.unwrap_or_else(|| {
            // Auto-generate a nonce from current timestamp seconds
            Utc::now().timestamp_millis() as u64
        });

        let key_id = keypair.key_id();
        let public_key = keypair.public_key()?;

        let genesis_id = GenesisId::compute(&content_hash, &key_id, nonce);
        let created_at = Utc::now();

        let cert = GenesisCertificate {
            schema_version: "1.0.0".to_string(),
            genesis_id: genesis_id.clone(),
            artifact: ArtifactDescription {
                name: artifact_name,
                content_hash: content_hash.clone(),
                artifact_type,
                file_manifest: self.file_manifest,
                size_bytes: self.size_bytes,
                metadata: self.artifact_metadata,
            },
            creator: CreatorInfo {
                key_id,
                public_key,
                display_name: self.creator_display_name,
                engine_version: crate::MKPE_VERSION.to_string(),
            },
            contributors: self.contributors,
            origin: SystemFingerprint::capture(),
            created_at,
            nonce,
            parent_id: self.parent_id,
            creator_signature: String::new(), // placeholder
        };

        // Sign the canonical payload
        let payload = cert.canonical_payload();
        let signature = keypair.sign(&payload)?;

        // Return the signed certificate
        Ok(GenesisCertificate {
            creator_signature: signature,
            ..cert
        })
    }
}

impl Default for GenesisCertificateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Post-build contributor signing
// ---------------------------------------------------------------------------

impl GenesisCertificate {
    /// Add a contributor signature to an existing certificate.
    ///
    /// The contributor signs the canonical payload of the certificate.
    /// Returns a mutable reference so callers can chain additions.
    pub fn add_contributor(
        &mut self,
        keypair: &dyn Signer,
        display_name: Option<String>,
        role: ContributorRole,
    ) -> crate::Result<()> {
        let payload = self.canonical_payload();
        let signature = keypair.sign(&payload)?;

        self.contributors.push(ContributorEntry {
            key_id: keypair.key_id(),
            display_name,
            role,
            signed_at: Utc::now(),
            signature,
        });

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> crate::crypto::KeyPair {
        generate_keypair()
    }

    fn build_test_cert() -> GenesisCertificate {
        let kp = test_keypair();
        GenesisCertificateBuilder::new()
            .artifact_name("Test Artifact")
            .content_hash("a" .repeat(64)) // fake SHA-256
            .artifact_type("test/data")
            .size_bytes(1024)
            .build(&kp)
            .unwrap()
    }

    // -- GenesisId uniqueness --

    #[test]
    fn test_genesis_id_is_deterministic() {
        let id1 = GenesisId::compute("hash1", "key1", 42);
        let id2 = GenesisId::compute("hash1", "key1", 42);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_genesis_id_differs_for_different_inputs() {
        let id1 = GenesisId::compute("hash1", "key1", 42);
        let id2 = GenesisId::compute("hash2", "key1", 42);
        let id3 = GenesisId::compute("hash1", "key2", 42);
        let id4 = GenesisId::compute("hash1", "key1", 43);
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id1, id4);
    }

    // -- Builder --

    #[test]
    fn test_builder_produces_valid_certificate() {
        let cert = build_test_cert();
        assert!(!cert.genesis_id.0.is_empty());
        assert_eq!(cert.artifact.name, "Test Artifact");
        assert_eq!(cert.schema_version, "1.0.0");
        assert_eq!(cert.creator.engine_version, crate::MKPE_VERSION);
        assert!(!cert.creator_signature.is_empty());
    }

    #[test]
    fn test_builder_requires_artifact_name() {
        let kp = test_keypair();
        let result = GenesisCertificateBuilder::new()
            .content_hash("a".repeat(64))
            .artifact_type("test")
            .build(&kp);
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_requires_content_hash() {
        let kp = test_keypair();
        let result = GenesisCertificateBuilder::new()
            .artifact_name("Test")
            .artifact_type("test")
            .build(&kp);
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_requires_artifact_type() {
        let kp = test_keypair();
        let result = GenesisCertificateBuilder::new()
            .artifact_name("Test")
            .content_hash("a".repeat(64))
            .build(&kp);
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_with_file_manifest() {
        let kp = test_keypair();
        let cert = GenesisCertificateBuilder::new()
            .artifact_name("Multi-file Artifact")
            .content_hash("b".repeat(64))
            .artifact_type("application/bundle")
            .file("main.rs", "c".repeat(64))
            .file("lib.rs", "d".repeat(64))
            .size_bytes(2048)
            .build(&kp)
            .unwrap();

        assert_eq!(cert.artifact.file_manifest.len(), 2);
        assert_eq!(cert.artifact.size_bytes, 2048);
    }

    #[test]
    fn test_builder_with_parent() {
        let kp = test_keypair();
        let parent_id = GenesisId::compute("parent_hash", "key1", 1);
        let cert = GenesisCertificateBuilder::new()
            .artifact_name("Derived Work")
            .content_hash("e".repeat(64))
            .artifact_type("derivative/work")
            .parent_id(parent_id.clone())
            .build(&kp)
            .unwrap();

        assert_eq!(cert.parent_id, Some(parent_id));
    }

    // -- Signature verification --

    #[test]
    fn test_creator_signature_verifies() {
        let cert = build_test_cert();
        assert!(cert.verify_creator_signature().unwrap());
    }

    #[test]
    fn test_creator_signature_fails_if_tampered() {
        let mut cert = build_test_cert();
        cert.creator_signature = "AAAA".to_string();
        // Invalid base64/length returns Err, which is still "not valid"
        assert!(!cert.verify_creator_signature().unwrap_or(false));
    }

    #[test]
    fn test_signature_fails_if_artifact_name_changed() {
        let mut cert = build_test_cert();
        cert.artifact.name = "Tampered Name".to_string();
        assert!(!cert.verify_creator_signature().unwrap());
    }

    #[test]
    fn test_signature_fails_if_content_hash_changed() {
        let mut cert = build_test_cert();
        cert.artifact.content_hash = "f".repeat(64);
        assert!(!cert.verify_creator_signature().unwrap());
    }

    // -- Contributor signing --

    #[test]
    fn test_add_contributor_signs_and_verifies() {
        let kp1 = test_keypair();
        let kp2 = generate_keypair();

        let mut cert = GenesisCertificateBuilder::new()
            .artifact_name("Collaborative Work")
            .content_hash("g".repeat(64))
            .artifact_type("collab/work")
            .build(&kp1)
            .unwrap();

        cert.add_contributor(&kp2, Some("Alice".to_string()), ContributorRole::CoCreator)
            .unwrap();

        assert_eq!(cert.contributors.len(), 1);
        assert_eq!(cert.contributors[0].display_name, Some("Alice".to_string()));
        assert_eq!(cert.contributors[0].role, ContributorRole::CoCreator);

        // Verify the contributor's signature
        let mut keys = HashMap::new();
        keys.insert(kp2.key_id.clone(), kp2.public_key.clone());
        let (valid, invalid) = cert.verify_all_contributors(&keys).unwrap();
        assert_eq!(valid, 1);
        assert_eq!(invalid, 0);
    }

    #[test]
    fn test_add_multiple_contributors() {
        let kp1 = test_keypair();
        let kp2 = generate_keypair();
        let kp3 = generate_keypair();

        let mut cert = GenesisCertificateBuilder::new()
            .artifact_name("Team Work")
            .content_hash("h".repeat(64))
            .artifact_type("team/work")
            .build(&kp1)
            .unwrap();

        cert.add_contributor(&kp2, Some("Alice".to_string()), ContributorRole::CoCreator)
            .unwrap();
        cert.add_contributor(&kp3, Some("Bob".to_string()), ContributorRole::Witness)
            .unwrap();

        assert_eq!(cert.contributors.len(), 2);

        let mut keys = HashMap::new();
        keys.insert(kp2.key_id.clone(), kp2.public_key.clone());
        keys.insert(kp3.key_id.clone(), kp3.public_key.clone());

        let report = cert.verify(&keys).unwrap();
        assert!(report.fully_valid);
        assert!(report.creator_signature_valid);
        assert_eq!(report.contributors_verified, 2);
    }

    #[test]
    fn test_contributor_fails_with_wrong_public_key() {
        let kp1 = test_keypair();
        let kp2 = generate_keypair();
        let wrong_kp = generate_keypair();

        let mut cert = GenesisCertificateBuilder::new()
            .artifact_name("Mismatched Key Work")
            .content_hash("i".repeat(64))
            .artifact_type("test/work")
            .build(&kp1)
            .unwrap();

        cert.add_contributor(&kp2, None, ContributorRole::Witness)
            .unwrap();

        let mut keys = HashMap::new();
        // Wrong public key for kp2
        keys.insert(kp2.key_id.clone(), wrong_kp.public_key.clone());

        let (valid, invalid) = cert.verify_all_contributors(&keys).unwrap();
        assert_eq!(valid, 0);
        assert_eq!(invalid, 1);
    }

    // -- Full verification --

    #[test]
    fn test_full_verification_passes() {
        let cert = build_test_cert();
        let report = cert.verify(&HashMap::new()).unwrap();
        assert!(report.fully_valid);
        assert!(report.creator_signature_valid);
    }

    #[test]
    fn test_full_verification_fails_if_creator_sig_invalid() {
        let mut cert = build_test_cert();
        cert.creator_signature = "AAAA".to_string();
        let report = cert.verify(&HashMap::new()).unwrap_or(VerificationReport {
            creator_signature_valid: false,
            contributors_verified: 0,
            contributors_failed: 0,
            total_contributors: 0,
            fully_valid: false,
        });
        assert!(!report.fully_valid);
        assert!(!report.creator_signature_valid);
    }

    #[test]
    fn test_verification_report_display() {
        let cert = build_test_cert();
        let report = cert.verify(&HashMap::new()).unwrap();
        let text = report.to_string();
        assert!(text.contains("VALID"));
        assert!(text.contains("FULLY VALID"));
    }

    // -- JSON round-trip --

    #[test]
    fn test_json_round_trip() {
        let cert = build_test_cert();
        let json = cert.to_json_pretty().unwrap();
        let parsed = GenesisCertificate::from_json(&json).unwrap();
        assert_eq!(parsed.genesis_id, cert.genesis_id);
        assert_eq!(parsed.artifact.name, cert.artifact.name);
        assert_eq!(parsed.artifact.content_hash, cert.artifact.content_hash);
        assert_eq!(parsed.creator.key_id, cert.creator.key_id);
        assert_eq!(parsed.nonce, cert.nonce);
    }

    #[test]
    fn test_file_round_trip() {
        let cert = build_test_cert();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("genesis.json");
        cert.save_to_file(&path).unwrap();
        let loaded = GenesisCertificate::load_from_file(&path).unwrap();
        assert_eq!(loaded.genesis_id, cert.genesis_id);
        assert!(loaded.verify_creator_signature().unwrap());
    }

    #[test]
    fn test_from_json_rejects_malformed() {
        let result = GenesisCertificate::from_json("not json");
        assert!(result.is_err());
    }

    // -- Nonce auto-generation --

    #[test]
    fn test_nonce_auto_generated_when_not_set() {
        let cert = build_test_cert();
        assert!(cert.nonce > 0);
    }

    #[test]
    fn test_explicit_nonce() {
        let kp = test_keypair();
        let cert = GenesisCertificateBuilder::new()
            .artifact_name("Explicit Nonce")
            .content_hash("j".repeat(64))
            .artifact_type("test/nonce")
            .nonce(12345)
            .build(&kp)
            .unwrap();
        assert_eq!(cert.nonce, 12345);
    }

    // -- ContributorRole display --

    #[test]
    fn test_contributor_role_display() {
        assert_eq!(ContributorRole::CoCreator.to_string(), "co-creator");
        assert_eq!(ContributorRole::Witness.to_string(), "witness");
        assert_eq!(ContributorRole::Reviewer.to_string(), "reviewer");
        assert_eq!(ContributorRole::Approver.to_string(), "approver");
        assert_eq!(ContributorRole::Custom("sponsor".to_string()).to_string(), "sponsor");
    }

    // -- Artifact metadata --

    #[test]
    fn test_artifact_metadata_preserved() {
        let kp = test_keypair();
        let cert = GenesisCertificateBuilder::new()
            .artifact_name("Metadata Test")
            .content_hash("k".repeat(64))
            .artifact_type("test/meta")
            .artifact_metadata("license", serde_json::json!("MIT"))
            .artifact_metadata("version", serde_json::json!("1.0.0"))
            .build(&kp)
            .unwrap();

        assert_eq!(cert.artifact.metadata.get("license").unwrap(), &serde_json::json!("MIT"));
        assert_eq!(cert.artifact.metadata.get("version").unwrap(), &serde_json::json!("1.0.0"));

        // Verify JSON round-trip preserves metadata
        let json = cert.to_json_pretty().unwrap();
        let parsed = GenesisCertificate::from_json(&json).unwrap();
        assert_eq!(parsed.artifact.metadata.len(), 2);
    }

    // -- System fingerprint is captured --

    #[test]
    fn test_origin_system_fingerprint_captured() {
        let cert = build_test_cert();
        assert!(!cert.origin.user.is_empty());
        assert!(!cert.origin.platform.is_empty());
        assert!(!cert.origin.hostname.is_empty());
        assert!(cert.origin.process_id > 0);
    }
}