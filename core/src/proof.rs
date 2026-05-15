//! Proof generation and verification
//!
//! Core MKPE proof system for creating verifiable chains of custody

use crate::manifest::SystemFingerprint;
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

/// Build a Merkle root from a list of hex-encoded SHA-256 hashes.
///
/// Constructs a pairwise binary Merkle tree:
/// - Decodes each hex string into a `[u8; 32]`.
/// - Builds internal nodes as `SHA-256(left || right)`.
/// - Pads odd levels by duplicating the last element.
/// - Returns the hex-encoded root hash.
pub fn build_merkle_root(hashes: &[String]) -> String {
    if hashes.is_empty() {
        let hasher = Sha256::new();
        return hex::encode(hasher.finalize());
    }

    // Sort hashes for deterministic tree regardless of input order
    let mut sorted: Vec<[u8; 32]> = hashes
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).expect("valid hex hash");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        })
        .collect();
    sorted.sort();

    while sorted.len() > 1 {
        if sorted.len() % 2 == 1 {
            sorted.push(*sorted.last().unwrap());
        }

        let mut next = Vec::with_capacity(sorted.len() / 2);
        for chunk in sorted.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            hasher.update(&chunk[1]);
            let hash: [u8; 32] = hasher.finalize().into();
            next.push(hash);
        }
        sorted = next;
    }

    hex::encode(sorted[0])
}

/// A Merkle inclusion proof verifying a leaf belongs to a tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleInclusionProof {
    /// Hex-encoded hash of the leaf being proved
    pub leaf_hash: String,
    /// Zero-based index of the leaf in the original list
    pub leaf_index: usize,
    /// Total number of leaves in the tree
    pub total_leaves: usize,
    /// Hex-encoded Merkle root this proof targets
    pub root_hash: String,
    /// Path from leaf to root: (sibling_hash, is_right_sibling).
    /// `is_right_sibling` is `true` when the sibling is to the right of the current node.
    pub path: Vec<(String, bool)>,
}

/// Generate an inclusion proof for a leaf at the given index.
///
/// Returns `None` if `leaf_index` is out of bounds or `hashes` is empty.
pub fn generate_inclusion_proof(
    hashes: &[String],
    leaf_index: usize,
) -> Option<MerkleInclusionProof> {
    if hashes.is_empty() || leaf_index >= hashes.len() {
        return None;
    }

    let total_leaves = hashes.len();
    let leaf_hash = hashes[leaf_index].clone();

    let mut current: Vec<[u8; 32]> = hashes
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).expect("valid hex hash");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        })
        .collect();

    let mut path = Vec::new();
    let mut idx = leaf_index;

    while current.len() > 1 {
        let len = current.len();

        let (sibling_idx, is_right) = if idx % 2 == 0 {
            // Current node is a left child; sibling is on the right.
            if idx + 1 < len {
                (idx + 1, true)
            } else {
                // Last element in an odd level — sibling is itself (padding).
                (idx, false)
            }
        } else {
            // Current node is a right child; sibling is on the left.
            (idx - 1, false)
        };

        path.push((hex::encode(current[sibling_idx]), is_right));

        // Pad odd level by duplicating the last element.
        if len % 2 == 1 {
            current.push(*current.last().unwrap());
        }

        let mut next = Vec::with_capacity(current.len() / 2);
        for chunk in current.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            hasher.update(&chunk[1]);
            let hash: [u8; 32] = hasher.finalize().into();
            next.push(hash);
        }
        current = next;
        idx /= 2;
    }

    let root_hash = hex::encode(current[0]);

    Some(MerkleInclusionProof {
        leaf_hash,
        leaf_index,
        total_leaves,
        root_hash,
        path,
    })
}

/// Verify an inclusion proof against an expected Merkle root.
///
/// Reconstructs the root by hashing the leaf with each sibling in the path,
/// then compares the result to `expected_root`.
pub fn verify_inclusion_proof(proof: &MerkleInclusionProof, expected_root: &str) -> bool {
    if proof.root_hash != expected_root {
        return false;
    }

    let bytes = hex::decode(&proof.leaf_hash).expect("valid hex");
    let mut current = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    };

    for (sibling_hex, is_right) in &proof.path {
        let sib_bytes = hex::decode(sibling_hex).expect("valid hex");
        let mut sibling = [0u8; 32];
        sibling.copy_from_slice(&sib_bytes);

        let mut hasher = Sha256::new();
        if *is_right {
            hasher.update(&current);
            hasher.update(&sibling);
        } else {
            hasher.update(&sibling);
            hasher.update(&current);
        }
        current = hasher.finalize().into();
    }

    hex::encode(current) == expected_root
}

/// Create a proof item from a file
pub fn create_proof_item<P: AsRef<Path>>(
    file_path: P,
    keypair: &dyn crate::crypto::Signer,
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
    keypair: &dyn crate::crypto::Signer,
    parent_bundle_id: Option<String>,
) -> Result<ProofBundle> {
    let bundle_id = uuid::Uuid::new_v4().to_string();

    // Build Merkle root from proof content hashes
    let hashes: Vec<String> = proofs.iter().map(|p| p.content_hash.clone()).collect();
    let root_hash = build_merkle_root(&hashes);

    let timestamp = chrono::Utc::now();
    let system_fingerprint = crate::manifest::SystemFingerprint::capture();

    // Sign the bundle: bundle_id, root_hash, timestamp, proof_count,
    // system_fingerprint fields, parent_bundle_id (same pattern as Manifest)
    let bundle_data = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        bundle_id,
        root_hash,
        timestamp,
        proofs.len(),
        system_fingerprint.user,
        system_fingerprint.platform,
        system_fingerprint.hostname,
        system_fingerprint.process_id,
        system_fingerprint.mkpe_version,
        parent_bundle_id.as_deref().unwrap_or(""),
    );
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
    let hashes: Vec<String> = bundle.proofs.iter().map(|p| p.content_hash.clone()).collect();
    let calculated_root = build_merkle_root(&hashes);

    // Check if root hash matches
    if calculated_root != bundle.root_hash {
        return Ok(false);
    }

    // Verify bundle signature
    let bundle_data = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        bundle.bundle_id,
        bundle.root_hash,
        bundle.timestamp,
        bundle.proofs.len(),
        bundle.system_fingerprint.user,
        bundle.system_fingerprint.platform,
        bundle.system_fingerprint.hostname,
        bundle.system_fingerprint.process_id,
        bundle.system_fingerprint.mkpe_version,
        bundle.parent_bundle_id.as_deref().unwrap_or(""),
    );
    crate::crypto::verify_signature(public_key, bundle_data.as_bytes(), &bundle.signature)
}

/// Recursively create proofs for all files in a directory
pub fn create_recursive_proofs<P: AsRef<Path>>(
    dir_path: P,
    keypair: &dyn crate::crypto::Signer,
) -> Result<Vec<ProofItem>> {
    let mut proofs = Vec::new();
    let root = dir_path.as_ref();

    fn visit_dirs(
        root: &Path,
        dir: &Path,
        proofs: &mut Vec<ProofItem>,
        keypair: &dyn crate::crypto::Signer,
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
