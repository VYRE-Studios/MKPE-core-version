//! .mkpe bundle format - self-contained provenance archives
//!
//! Binary format specification v1.0:
//! - 32-byte structured header with magic, version, flags, section sizes
//! - JSON manifest (plaintext, human-readable)
//! - Binary proof data (Merkle tree)
//! - Ed25519 signature block
//! - 8-byte footer with reverse magic and CRC32

use crate::{Manifest, MkpeError, ProofBundle, ProofItem, Result};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// State marker for an unverified archive
#[derive(Debug, Clone)]
pub struct Unverified;

/// State marker for a cryptographically verified archive
#[derive(Debug, Clone)]
pub struct Verified;

/// Wrapper ensuring an archive has been verified
#[derive(Debug, Clone)]
pub struct VerifiedMkpeArchive(MkpeArchive);

impl VerifiedMkpeArchive {
    /// Access the inner archive (read-only)
    pub fn inner(&self) -> &MkpeArchive {
        &self.0
    }

    /// Unwrap the inner archive
    pub fn into_inner(self) -> MkpeArchive {
        self.0
    }
}

/// Magic number identifying MKPE files: ASCII "MKPE"
pub const MKPE_MAGIC: &[u8; 4] = b"MKPE";

/// Footer magic: reverse of MKPE
pub const MKPE_FOOTER_MAGIC: &[u8; 4] = b"EPKM";

/// Format version
pub const FORMAT_VERSION: u8 = 0x02;
pub const FORMAT_VERSION_V1: u8 = 0x01;

/// Flags
pub const FLAG_ENCRYPTED: u8 = 0x01;
pub const FLAG_COMPRESSED: u8 = 0x02;

/// 32-byte structured header
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MkpeHeader {
    /// Magic: "MKPE" (4 bytes)
    pub magic: [u8; 4],
    /// Format version (1 byte)
    pub version: u8,
    /// Flags: bit 0 = encrypted, bit 1 = compressed (1 byte)
    pub flags: u8,
    /// Size of manifest section in bytes (8 bytes, little-endian)
    pub manifest_size: u64,
    /// Size of proof section in bytes (8 bytes, little-endian)
    pub proof_size: u64,
    /// Size of signature block in bytes (8 bytes, little-endian)
    pub signature_size: u64,
    /// Reserved for future use (2 bytes)
    pub reserved: [u8; 2],
}

impl MkpeHeader {
    /// Create a new header
    pub fn new(manifest_size: u64, proof_size: u64, signature_size: u64) -> Self {
        Self {
            magic: *MKPE_MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            manifest_size,
            proof_size,
            signature_size,
            reserved: [0, 0],
        }
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&self.magic);
        bytes[4] = self.version;
        bytes[5] = self.flags;
        bytes[6..14].copy_from_slice(&self.manifest_size.to_le_bytes());
        bytes[14..22].copy_from_slice(&self.proof_size.to_le_bytes());
        bytes[22..30].copy_from_slice(&self.signature_size.to_le_bytes());
        bytes[30..32].copy_from_slice(&self.reserved);
        bytes
    }

    /// Deserialize header from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
        if &magic != MKPE_MAGIC {
            return Err(MkpeError::BundleError(
                "Invalid MKPE magic header".to_string(),
            ));
        }

        Ok(Self {
            magic,
            version: bytes[4],
            flags: bytes[5],
            manifest_size: u64::from_le_bytes(bytes[6..14].try_into().unwrap()),
            proof_size: u64::from_le_bytes(bytes[14..22].try_into().unwrap()),
            signature_size: u64::from_le_bytes(bytes[22..30].try_into().unwrap()),
            reserved: [bytes[30], bytes[31]],
        })
    }
}

/// 8-byte footer for validation
#[derive(Debug, Clone)]
pub struct MkpeFooter {
    /// Reverse magic: "EPKM"
    pub magic: [u8; 4],
    /// CRC32 of header + manifest size + proof size
    pub crc32: u32,
}

impl MkpeFooter {
    /// Create a new footer
    pub fn new(crc32: u32) -> Self {
        Self {
            magic: *MKPE_FOOTER_MAGIC,
            crc32,
        }
    }

    /// Serialize footer to bytes
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&self.magic);
        bytes[4..8].copy_from_slice(&self.crc32.to_le_bytes());
        bytes
    }

    /// Deserialize footer from bytes
    pub fn from_bytes(bytes: &[u8; 8]) -> Result<Self> {
        let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
        if &magic != MKPE_FOOTER_MAGIC {
            return Err(MkpeError::BundleError(
                "Invalid MKPE footer magic".to_string(),
            ));
        }

        Ok(Self {
            magic,
            crc32: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        })
    }
}

/// Complete MKPE archive structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MkpeArchive {
    /// Self-verifying manifest
    pub manifest: Manifest,
    /// Proof bundles contained in this archive
    pub bundles: Vec<ProofBundle>,
    /// Creation metadata
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Archive format version
    pub format_version: String,
}

/// Result of verifying current artifact bytes against an MKPE sidecar bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactVerificationReport {
    pub verified_proofs: usize,
    pub root_hash: String,
    pub manifest_id: String,
}

impl MkpeArchive {
    /// Create a new MKPE archive
    pub fn new(manifest: Manifest, bundles: Vec<ProofBundle>) -> Self {
        Self {
            manifest,
            bundles,
            created_at: chrono::Utc::now(),
            format_version: "1.0.0".to_string(),
        }
    }

    /// Save archive to a .mkpe file using binary format v1.0
    pub fn save<P: AsRef<Path>>(&self, path: P, keypair: &crate::crypto::KeyPair) -> Result<()> {
        let mut file = File::create(path)?;

        // Section 1: Serialize manifest to canonical JSON (no extra whitespace)
        let manifest_json = serde_json::to_vec(&self.manifest)?;

        // Section 2: Serialize proof data with full metadata
        let proof_data = self.serialize_proof_section()?;

        // Section 3: Create signature block
        // Sign SHA256(manifest || proof)
        let signature_block = self.create_signature_block(&manifest_json, &proof_data, keypair)?;

        // Create header with section sizes
        let header = MkpeHeader::new(
            manifest_json.len() as u64,
            proof_data.len() as u64,
            signature_block.len() as u64,
        );

        let header_bytes = header.to_bytes();

        // Calculate CRC32 for footer - FULL FILE INTEGRITY (v2)
        let crc32 =
            calculate_crc32(&[&header_bytes, &manifest_json, &proof_data, &signature_block]);

        // Create footer
        let footer = MkpeFooter::new(crc32);
        let footer_bytes = footer.to_bytes();

        // Write everything in order
        file.write_all(&header_bytes)?; // 32 bytes
        file.write_all(&manifest_json)?; // Variable
        file.write_all(&proof_data)?; // Variable
        file.write_all(&signature_block)?; // Variable
        file.write_all(&footer_bytes)?; // 8 bytes

        Ok(())
    }

    /// Serialize proof section with full proof metadata.
    fn serialize_proof_section(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.bundles).map_err(MkpeError::from)
    }

    /// Create signature block (public key + signature)
    fn create_signature_block(
        &self,
        manifest: &[u8],
        proof_data: &[u8],
        keypair: &crate::crypto::KeyPair,
    ) -> Result<Vec<u8>> {
        // Calculate SHA256 of all data to be signed
        let mut hasher = Sha256::new();
        hasher.update(manifest);
        hasher.update(proof_data);
        let data_hash = hasher.finalize();

        // Actually sign the hash with the keypair
        let signature_b64 = keypair.sign(&data_hash)?;

        let mut signature_block = Vec::new();

        // Decode public key from base64
        let public_key_bytes = general_purpose::STANDARD
            .decode(&keypair.public_key)
            .map_err(|e| MkpeError::BundleError(format!("Invalid public key: {}", e)))?;

        if public_key_bytes.len() != 32 {
            return Err(MkpeError::BundleError(
                "Public key must be 32 bytes".to_string(),
            ));
        }

        // Write public key (32 bytes)
        signature_block.extend_from_slice(&public_key_bytes);

        // Decode the signature we just created
        let signature_bytes = general_purpose::STANDARD
            .decode(&signature_b64)
            .map_err(|e| MkpeError::BundleError(format!("Invalid signature: {}", e)))?;

        if signature_bytes.len() != 64 {
            return Err(MkpeError::BundleError(
                "Signature must be 64 bytes".to_string(),
            ));
        }

        // Write signature (64 bytes)
        signature_block.extend_from_slice(&signature_bytes);

        Ok(signature_block)
    }

    /// Load archive from a .mkpe file using binary format v1.0
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path)?;

        // Read and parse 32-byte header
        let mut header_bytes = [0u8; 32];
        file.read_exact(&mut header_bytes)?;
        let header = MkpeHeader::from_bytes(&header_bytes)?;

        // Verify version
        // Verify version
        if header.version != FORMAT_VERSION && header.version != FORMAT_VERSION_V1 {
            return Err(MkpeError::BundleError(format!(
                "Unsupported format version: {}",
                header.version
            )));
        }

        // Read manifest section
        let mut manifest_bytes = vec![0u8; header.manifest_size as usize];
        file.read_exact(&mut manifest_bytes)?;

        // Read proof section
        let mut proof_bytes = vec![0u8; header.proof_size as usize];
        file.read_exact(&mut proof_bytes)?;

        // Read signature block
        let mut signature_bytes = vec![0u8; header.signature_size as usize];
        file.read_exact(&mut signature_bytes)?;

        // Read and verify footer
        let mut footer_bytes = [0u8; 8];
        file.read_exact(&mut footer_bytes)?;
        let footer = MkpeFooter::from_bytes(&footer_bytes)?;

        // Verify CRC32
        let calculated_crc = if header.version == FORMAT_VERSION_V1 {
            // v1: Weak CRC (header + manifest size)
            calculate_crc32(&[&header_bytes, &manifest_bytes.len().to_le_bytes()])
        } else {
            // v2+: Strong CRC (Full content)
            calculate_crc32(&[
                &header_bytes,
                &manifest_bytes,
                &proof_bytes,
                &signature_bytes,
            ])
        };
        if calculated_crc != footer.crc32 {
            return Err(MkpeError::BundleError(
                "CRC32 mismatch - file may be corrupted".to_string(),
            ));
        }

        // Deserialize manifest
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;

        // Parse proof section
        let bundles = Self::deserialize_proof_section(&proof_bytes, &manifest)?;

        // Verify signature
        Self::verify_signature_block(&manifest_bytes, &proof_bytes, &signature_bytes, &manifest)?;

        Ok(MkpeArchive {
            manifest,
            bundles,
            created_at: chrono::Utc::now(),
            format_version: "1.0.0".to_string(),
        })
    }

    /// Deserialize proof section, supporting current metadata JSON and legacy hash-only data.
    fn deserialize_proof_section(data: &[u8], manifest: &Manifest) -> Result<Vec<ProofBundle>> {
        if data.len() < 4 {
            return Ok(Vec::new());
        }

        if let Ok(bundles) = serde_json::from_slice::<Vec<ProofBundle>>(data) {
            return Ok(bundles);
        }

        // Read count
        let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;

        // Each hash is 32 bytes
        let expected_size = 4 + (count * 32);
        if data.len() != expected_size {
            return Err(MkpeError::BundleError(format!(
                "Proof section size mismatch: expected {}, got {}",
                expected_size,
                data.len()
            )));
        }

        // For now, create a single bundle with all proofs
        // (In a full implementation, you'd reconstruct the original bundle structure)
        let mut proofs = Vec::new();

        for i in 0..count {
            let offset = 4 + (i * 32);
            let hash_bytes = &data[offset..offset + 32];
            let hash_hex = hex::encode(hash_bytes);

            // Create a proof item (note: path and other metadata lost in binary format)
            // In production, you'd store this metadata separately
            let proof = crate::proof::ProofItem {
                id: uuid::Uuid::new_v4().to_string(),
                content_hash: hash_hex,
                path: std::path::PathBuf::from("unknown"),
                timestamp: chrono::Utc::now(),
                signature: String::new(),
                metadata: std::collections::HashMap::new(),
            };

            proofs.push(proof);
        }

        if proofs.is_empty() {
            return Ok(Vec::new());
        }

        // Create a single bundle
        let bundle = ProofBundle {
            bundle_id: uuid::Uuid::new_v4().to_string(),
            root_hash: manifest.bundle_root_hash.clone(),
            proofs,
            timestamp: chrono::Utc::now(),
            signature: manifest.signature.clone(),
            system_fingerprint: crate::proof::SystemFingerprint::capture(),
            parent_bundle_id: None,
        };

        Ok(vec![bundle])
    }

    /// Verify signature block
    fn verify_signature_block(
        manifest: &[u8],
        proof_data: &[u8],
        signature_block: &[u8],
        _manifest_obj: &Manifest,
    ) -> Result<()> {
        if signature_block.len() != 96 {
            return Err(MkpeError::BundleError(
                "Invalid signature block size".to_string(),
            ));
        }

        // Extract public key (32 bytes) and signature (64 bytes)
        let public_key_bytes = &signature_block[0..32];
        let signature_bytes = &signature_block[32..96];

        // Calculate data hash
        let mut hasher = Sha256::new();
        hasher.update(manifest);
        hasher.update(proof_data);
        let data_hash = hasher.finalize();

        // Verify Ed25519 signature
        let verifying_key = VerifyingKey::from_bytes(public_key_bytes.try_into().unwrap())
            .map_err(|e| MkpeError::BundleError(format!("Invalid public key: {}", e)))?;

        let signature = Signature::from_bytes(signature_bytes.try_into().unwrap());

        verifying_key.verify(&data_hash, &signature).map_err(|_| {
            MkpeError::VerificationFailed("Signature verification failed".to_string())
        })?;

        Ok(())
    }

    /// Verify the integrity of this archive and return a Verified wrapper
    /// Note: Bundle signature is verified during load() via verify_signature_block
    /// This method performs additional manifest consistency checks and enforces monotonicity.
    pub fn verify(self) -> Result<VerifiedMkpeArchive> {
        // The bundle signature was already verified in load()
        // Here we verify the inner manifest signature and consistency

        // 1. Verify Manifest Inner Signature
        if !self.manifest.verify()? {
            return Err(MkpeError::VerificationFailed(
                "Inner manifest signature invalid".into(),
            ));
        }

        // Verify manifest data is consistent
        let total_proofs: usize = self.bundles.iter().map(|b| b.proofs.len()).sum();
        if self.manifest.proof_count != total_proofs {
            return Err(MkpeError::VerificationFailed(format!(
                "Proof count mismatch: manifest says {}, found {}",
                self.manifest.proof_count, total_proofs
            )));
        }

        // Verify root hash matches bundles
        let mut hasher = Sha256::new();
        for bundle in &self.bundles {
            // Monotonicity Check: Bundle timestamp cannot be older than proofs
            for proof in &bundle.proofs {
                if proof.timestamp > bundle.timestamp {
                    return Err(MkpeError::VerificationFailed(format!(
                        "Invariant Violation: Time Travel Detected. Proof {} ({}) is newer than its container bundle ({})",
                        proof.id, proof.timestamp, bundle.timestamp
                    )));
                }
                hasher.update(proof.content_hash.as_bytes());
            }
        }
        let calculated_root = hex::encode(hasher.finalize());

        if calculated_root != self.manifest.bundle_root_hash {
            return Err(MkpeError::VerificationFailed("Root hash mismatch".into()));
        }

        Ok(VerifiedMkpeArchive(self))
    }

    /// Get archive statistics
    pub fn stats(&self) -> ArchiveStats {
        let total_proofs: usize = self.bundles.iter().map(|b| b.proofs.len()).sum();

        ArchiveStats {
            bundle_count: self.bundles.len(),
            total_proof_items: total_proofs,
            created_at: self.created_at,
            manifest_id: self.manifest.manifest_id.clone(),
            root_hash: self.manifest.bundle_root_hash.clone(),
        }
    }

    /// Verify current file or folder bytes against this signed MKPE proof bundle.
    pub fn verify_artifact<P: AsRef<Path>>(
        &self,
        artifact_path: P,
    ) -> Result<ArtifactVerificationReport> {
        self.clone().verify()?;

        let artifact_path = artifact_path.as_ref();
        if artifact_path.is_dir() {
            assert_directory_inventory_matches(artifact_path, &self.bundles)?;
        }

        for bundle in &self.bundles {
            for proof in &bundle.proofs {
                let current_path = resolve_proof_path(artifact_path, proof);
                if !crate::proof::verify_proof_item(
                    proof,
                    &current_path,
                    &self.manifest.verifier_public_key,
                )? {
                    return Err(MkpeError::VerificationFailed(format!(
                        "Artifact bytes do not match MKPE proof for {}",
                        proof.path.display()
                    )));
                }
            }
        }

        Ok(ArtifactVerificationReport {
            verified_proofs: self.bundles.iter().map(|bundle| bundle.proofs.len()).sum(),
            root_hash: self.manifest.bundle_root_hash.clone(),
            manifest_id: self.manifest.manifest_id.clone(),
        })
    }
}

/// Statistics about an archive
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveStats {
    pub bundle_count: usize,
    pub total_proof_items: usize,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub manifest_id: String,
    pub root_hash: String,
}

/// Calculate CRC32 checksum
fn calculate_crc32(data_slices: &[&[u8]]) -> u32 {
    const CRC32_TABLE: [u32; 256] = generate_crc32_table();

    let mut crc: u32 = 0xFFFF_FFFF;

    for data in data_slices {
        for &byte in *data {
            let index = ((crc ^ byte as u32) & 0xFF) as usize;
            crc = (crc >> 8) ^ CRC32_TABLE[index];
        }
    }

    !crc
}

/// Generate CRC32 lookup table
const fn generate_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;

    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;

        while j < 8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }

        table[i] = crc;
        i += 1;
    }

    table
}

/// Create a .mkpe bundle from a directory
pub fn create_mkpe_bundle<P: AsRef<Path>>(
    dir_path: P,
    keypair: &crate::crypto::KeyPair,
    output_path: P,
) -> Result<MkpeArchive> {
    // Create recursive proofs
    let proofs = create_artifact_proofs(dir_path.as_ref(), keypair)?;

    // Create proof bundle
    let bundle = crate::proof::create_proof_bundle(proofs, keypair, None)?;

    // Create manifest
    let mut manifest = Manifest::new(
        bundle.root_hash.clone(),
        bundle.proofs.len(),
        keypair.public_key.clone(),
        None,
    );
    manifest.sign(keypair)?;

    // Create archive
    let archive = MkpeArchive::new(manifest, vec![bundle]);

    // Save to file with keypair for bundle signature
    archive.save(output_path, keypair)?;

    Ok(archive)
}

fn create_artifact_proofs(path: &Path, keypair: &crate::crypto::KeyPair) -> Result<Vec<ProofItem>> {
    if path.is_file() {
        let mut proof = crate::proof::create_proof_item(path, keypair)?;
        proof.path = path
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| path.to_path_buf());
        return Ok(vec![proof]);
    }

    let mut proofs = Vec::new();
    collect_artifact_proofs(path, path, keypair, &mut proofs)?;
    proofs.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(proofs)
}

fn collect_artifact_proofs(
    root: &Path,
    dir: &Path,
    keypair: &crate::crypto::KeyPair,
    proofs: &mut Vec<ProofItem>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_artifact_proofs(root, &path, keypair, proofs)?;
            continue;
        }
        if is_mkpe_sidecar_file(&path) {
            continue;
        }

        let mut proof = crate::proof::create_proof_item(&path, keypair)?;
        proof.path = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        proofs.push(proof);
    }

    Ok(())
}

fn assert_directory_inventory_matches(root: &Path, bundles: &[ProofBundle]) -> Result<()> {
    let proven_paths: BTreeSet<PathBuf> = bundles
        .iter()
        .flat_map(|bundle| bundle.proofs.iter().map(|proof| proof.path.clone()))
        .collect();
    let current_paths = collect_current_artifact_paths(root)?;

    if proven_paths == current_paths {
        return Ok(());
    }

    let missing: Vec<String> = proven_paths
        .difference(&current_paths)
        .map(|path| path.display().to_string())
        .collect();
    let extra: Vec<String> = current_paths
        .difference(&proven_paths)
        .map(|path| path.display().to_string())
        .collect();

    Err(MkpeError::VerificationFailed(format!(
        "Artifact inventory changed. Missing proven files: [{}]. Unproven files: [{}]",
        missing.join(", "),
        extra.join(", ")
    )))
}

fn collect_current_artifact_paths(root: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut paths = BTreeSet::new();
    collect_current_artifact_paths_inner(root, root, &mut paths)?;
    Ok(paths)
}

fn collect_current_artifact_paths_inner(
    root: &Path,
    dir: &Path,
    paths: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_current_artifact_paths_inner(root, &path, paths)?;
            continue;
        }
        if is_mkpe_sidecar_file(&path) {
            continue;
        }

        paths.insert(path.strip_prefix(root).unwrap_or(&path).to_path_buf());
    }

    Ok(())
}

fn is_mkpe_sidecar_file(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some(".mkpe")
        || path.extension().and_then(|ext| ext.to_str()) == Some("mkpe")
}

fn resolve_proof_path(artifact_path: &Path, proof: &ProofItem) -> PathBuf {
    if artifact_path.is_file() {
        return artifact_path.to_path_buf();
    }

    artifact_path.join(&proof.path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_mkpe_archive_create_and_load() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let keypair = crate::crypto::generate_keypair();

        // Create test files
        for i in 0..3 {
            let file_path = temp_dir.path().join(format!("test{}.txt", i));
            std::fs::write(file_path, format!("Test content {}", i))?;
        }

        // Create archive
        let archive_path = temp_dir.path().join("test.mkpe");
        let archive = create_mkpe_bundle(temp_dir.path(), &keypair, &archive_path)?;

        // Load archive
        let loaded = MkpeArchive::load(&archive_path)?;

        assert_eq!(loaded.bundles.len(), archive.bundles.len());
        assert_eq!(loaded.manifest.manifest_id, archive.manifest.manifest_id);

        Ok(())
    }

    #[test]
    fn test_mkpe_archive_preserves_proof_metadata_on_load() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let keypair = crate::crypto::generate_keypair();

        let file_path = temp_dir.path().join("lineage.txt");
        std::fs::write(&file_path, b"Every byte carries provenance")?;

        let archive_path = temp_dir.path().join("lineage.mkpe");
        let archive = create_mkpe_bundle(temp_dir.path(), &keypair, &archive_path)?;
        let loaded = MkpeArchive::load(&archive_path)?;

        let original_proof = &archive.bundles[0].proofs[0];
        let loaded_proof = &loaded.bundles[0].proofs[0];

        assert_eq!(loaded.bundles[0].bundle_id, archive.bundles[0].bundle_id);
        assert_eq!(loaded.bundles[0].signature, archive.bundles[0].signature);
        assert_eq!(loaded_proof.id, original_proof.id);
        assert_eq!(loaded_proof.path, original_proof.path);
        assert_eq!(loaded_proof.signature, original_proof.signature);

        Ok(())
    }

    #[test]
    fn test_mkpe_archive_verification() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let keypair = crate::crypto::generate_keypair();

        let file_path = temp_dir.path().join("test.txt");
        std::fs::write(&file_path, b"Test content")?;

        let archive_path = temp_dir.path().join("test.mkpe");
        let archive = create_mkpe_bundle(temp_dir.path(), &keypair, &archive_path)?;

        let is_valid = archive.verify().is_ok();
        assert!(is_valid);

        Ok(())
    }

    #[test]
    fn test_verify_artifact_detects_modified_file_bytes() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let keypair = crate::crypto::generate_keypair();

        let file_path = temp_dir.path().join("asset.txt");
        std::fs::write(&file_path, b"original byte dna")?;

        let archive_path = temp_dir.path().join("asset.mkpe");
        create_mkpe_bundle(&file_path, &keypair, &archive_path)?;

        let archive = MkpeArchive::load(&archive_path)?;
        let report = archive.verify_artifact(&file_path)?;
        assert_eq!(report.verified_proofs, 1);

        std::fs::write(&file_path, b"tampered byte dna")?;

        let tampered = archive.verify_artifact(&file_path);
        assert!(tampered.is_err());

        Ok(())
    }

    #[test]
    fn test_verify_artifact_detects_new_unproven_folder_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let keypair = crate::crypto::generate_keypair();

        let artifact_dir = temp_dir.path().join("artifact");
        std::fs::create_dir(&artifact_dir)?;
        std::fs::write(artifact_dir.join("a.txt"), b"first proven bytes")?;

        let archive_path = temp_dir.path().join("artifact.mkpe");
        create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;

        let archive = MkpeArchive::load(&archive_path)?;
        archive.verify_artifact(&artifact_dir)?;

        std::fs::write(artifact_dir.join("b.txt"), b"new unproven bytes")?;

        let tampered = archive.verify_artifact(&artifact_dir);
        assert!(tampered.is_err());

        Ok(())
    }

    #[test]
    fn test_magic_header() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let keypair = crate::crypto::generate_keypair();

        let file_path = temp_dir.path().join("test.txt");
        std::fs::write(&file_path, b"Test")?;

        let archive_path = temp_dir.path().join("test.mkpe");
        create_mkpe_bundle(temp_dir.path(), &keypair, &archive_path)?;

        // Read magic header
        let mut file = File::open(&archive_path)?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;

        assert_eq!(&magic, MKPE_MAGIC);

        Ok(())
    }
}
