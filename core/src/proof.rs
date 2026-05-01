//! Proof generation and verification
//!
//! Core MKPE proof system for creating verifiable chains of custody

use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A single proof item representing a verified file or component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofItem {
    /// Unique identifier for this proof
    pub id: String,
    /// SHA-256 hash of the content
    pub content_hash: String,
    /// File path or identifier
    pub path: PathBuf,
    /// Timestamp when proof was created
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Cryptographic signature of this proof
    pub signature: String,
    /// Optional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// A bundle of proofs forming a Merkle tree structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundle {
    /// Bundle identifier
    pub bundle_id: String,
    /// Root hash (Merkle root) of all child proofs
    pub root_hash: String,
    /// Individual proof items in this bundle
    pub proofs: Vec<ProofItem>,
    /// Timestamp when bundle was created
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Digital signature of the entire bundle
    pub signature: String,
    /// System fingerprint
    pub system_fingerprint: SystemFingerprint,
    /// Optional parent bundle ID for chaining
    pub parent_bundle_id: Option<String>,
}

/// System fingerprint for provenance tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemFingerprint {
    /// Username
    pub user: String,
    /// Platform (Windows, Linux, macOS)
    pub platform: String,
    /// Hostname
    pub hostname: String,
    /// Process ID
    pub process_id: u32,
    /// MKPE version
    pub mkpe_version: String,
}

impl SystemFingerprint {
    /// Create a fingerprint of the current system
    pub fn capture() -> Self {
        Self {
            user: whoami::username(),
            platform: whoami::platform().to_string(),
            hostname: whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
            process_id: std::process::id(),
            mkpe_version: crate::MKPE_VERSION.to_string(),
        }
    }
}

/// Create a proof item from a file
pub fn create_proof_item<P: AsRef<Path>>(
    file_path: P,
    keypair: &crate::crypto::KeyPair,
) -> Result<ProofItem> {
    let path = file_path.as_ref();
    let contents = std::fs::read(path)?;

    // Calculate SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(&contents);
    let content_hash = hex::encode(hasher.finalize());

    let id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now();

    // Sign the proof data
    let proof_data = format!("{}:{}:{}", id, content_hash, timestamp);
    let signature = keypair.sign(proof_data.as_bytes())?;

    Ok(ProofItem {
        id,
        content_hash,
        path: path.to_path_buf(),
        timestamp,
        signature,
        metadata: HashMap::new(),
    })
}

/// Create a proof bundle from multiple proof items
pub fn create_proof_bundle(
    proofs: Vec<ProofItem>,
    keypair: &crate::crypto::KeyPair,
    parent_bundle_id: Option<String>,
) -> Result<ProofBundle> {
    let bundle_id = uuid::Uuid::new_v4().to_string();

    // Calculate Merkle root from all proof hashes
    let mut hasher = Sha256::new();
    for proof in &proofs {
        hasher.update(proof.content_hash.as_bytes());
    }
    let root_hash = hex::encode(hasher.finalize());

    let timestamp = chrono::Utc::now();
    let system_fingerprint = SystemFingerprint::capture();

    // Sign the bundle
    let bundle_data = format!("{}:{}:{}", bundle_id, root_hash, timestamp);
    let signature = keypair.sign(bundle_data.as_bytes())?;

    Ok(ProofBundle {
        bundle_id,
        root_hash,
        proofs,
        timestamp,
        signature,
        system_fingerprint,
        parent_bundle_id,
    })
}

/// Verify a proof item's integrity
pub fn verify_proof_item(proof: &ProofItem, file_path: &Path, public_key: &str) -> Result<bool> {
    // Recalculate file hash
    let contents = std::fs::read(file_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&contents);
    let current_hash = hex::encode(hasher.finalize());

    // Check if hash matches
    if current_hash != proof.content_hash {
        return Ok(false);
    }

    // Verify signature
    let proof_data = format!("{}:{}:{}", proof.id, proof.content_hash, proof.timestamp);
    crate::crypto::verify_signature(public_key, proof_data.as_bytes(), &proof.signature)
}

/// Verify a proof bundle's integrity
pub fn verify_proof_bundle(bundle: &ProofBundle, public_key: &str) -> Result<bool> {
    // Recalculate Merkle root
    let mut hasher = Sha256::new();
    for proof in &bundle.proofs {
        hasher.update(proof.content_hash.as_bytes());
    }
    let calculated_root = hex::encode(hasher.finalize());

    // Check if root hash matches
    if calculated_root != bundle.root_hash {
        return Ok(false);
    }

    // Verify bundle signature
    let bundle_data = format!(
        "{}:{}:{}",
        bundle.bundle_id, bundle.root_hash, bundle.timestamp
    );
    crate::crypto::verify_signature(public_key, bundle_data.as_bytes(), &bundle.signature)
}

/// Recursively create proofs for all files in a directory
pub fn create_recursive_proofs<P: AsRef<Path>>(
    dir_path: P,
    keypair: &crate::crypto::KeyPair,
) -> Result<Vec<ProofItem>> {
    let mut proofs = Vec::new();
    let root = dir_path.as_ref();

    fn visit_dirs(
        root: &Path,
        dir: &Path,
        proofs: &mut Vec<ProofItem>,
        keypair: &crate::crypto::KeyPair,
    ) -> Result<()> {
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    visit_dirs(root, &path, proofs, keypair)?;
                } else {
                    let mut proof = create_proof_item(&path, keypair)?;
                    proof.path = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
                    proofs.push(proof);
                }
            }
        }
        Ok(())
    }

    visit_dirs(root, root, &mut proofs, keypair)?;
    proofs.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(proofs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_proof_item_creation() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, b"Test content")?;

        let keypair = crate::crypto::generate_keypair();
        let proof = create_proof_item(&test_file, &keypair)?;

        assert!(!proof.id.is_empty());
        assert!(!proof.content_hash.is_empty());
        assert_eq!(proof.content_hash.len(), 64); // SHA-256 hex length

        Ok(())
    }

    #[test]
    fn test_proof_verification() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, b"Test content")?;

        let keypair = crate::crypto::generate_keypair();
        let proof = create_proof_item(&test_file, &keypair)?;

        let is_valid = verify_proof_item(&proof, &test_file, &keypair.public_key)?;
        assert!(is_valid);

        // Modify file and verify it fails
        std::fs::write(&test_file, b"Modified content")?;
        let is_invalid = verify_proof_item(&proof, &test_file, &keypair.public_key)?;
        assert!(!is_invalid);

        Ok(())
    }

    #[test]
    fn test_proof_bundle_creation() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let keypair = crate::crypto::generate_keypair();

        let mut proofs = Vec::new();
        for i in 0..3 {
            let file_path = temp_dir.path().join(format!("file{}.txt", i));
            std::fs::write(&file_path, format!("Content {}", i))?;
            let proof = create_proof_item(&file_path, &keypair)?;
            proofs.push(proof);
        }

        let bundle = create_proof_bundle(proofs, &keypair, None)?;

        assert!(!bundle.bundle_id.is_empty());
        assert!(!bundle.root_hash.is_empty());
        assert_eq!(bundle.proofs.len(), 3);

        let is_valid = verify_proof_bundle(&bundle, &keypair.public_key)?;
        assert!(is_valid);

        Ok(())
    }

    #[test]
    fn test_recursive_proofs_use_relative_sorted_paths() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let keypair = crate::crypto::generate_keypair();

        let nested_dir = temp_dir.path().join("b");
        std::fs::create_dir(&nested_dir)?;
        std::fs::write(nested_dir.join("nested.txt"), b"nested")?;
        std::fs::write(temp_dir.path().join("a.txt"), b"root")?;

        let proofs = create_recursive_proofs(temp_dir.path(), &keypair)?;
        let paths: Vec<PathBuf> = proofs.iter().map(|proof| proof.path.clone()).collect();

        assert_eq!(
            paths,
            vec![
                PathBuf::from("a.txt"),
                PathBuf::from("b").join("nested.txt")
            ]
        );

        Ok(())
    }
}
