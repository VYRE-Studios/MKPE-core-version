//! Self-verifying manifest system for MKPE
//!
//! Manifests provide human and machine-readable metadata about
//! the provenance bundle with cryptographic verification

use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// System fingerprint for provenance tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemFingerprint {
    /// Username who created this manifest
    pub user: String,
    /// Platform (Windows, Linux, macOS)
    pub platform: String,
    /// Hostname
    pub hostname: String,
    /// Process ID when created
    pub process_id: u32,
    /// MKPE version used
    pub mkpe_version: String,
    /// Timestamp of creation
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl SystemFingerprint {
    /// Capture current system fingerprint
    pub fn capture() -> Self {
        Self {
            user: whoami::username(),
            platform: whoami::platform().to_string(),
            hostname: whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
            process_id: std::process::id(),
            mkpe_version: crate::MKPE_VERSION.to_string(),
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Self-verifying manifest for MKPE bundles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// MKPE schema version
    pub schema_version: String,
    /// Engine version that created this
    pub engine_version: String,
    /// Unique manifest ID
    pub manifest_id: String,
    /// System fingerprint
    pub system_fingerprint: SystemFingerprint,
    /// Root hash of the bundle
    pub bundle_root_hash: String,
    /// Total number of proof items
    pub proof_count: usize,
    /// Timestamp when manifest was sealed
    pub sealed_timestamp: chrono::DateTime<chrono::Utc>,
    /// Public key used for verification
    pub verifier_public_key: String,
    /// Signature of this manifest
    pub signature: String,
	/// Optional parent manifest ID for chaining
	pub parent_manifest_id: Option<String>,
	/// Optional monotonic nonce for replay protection
	pub nonce: Option<u64>,
	/// Custom metadata
	pub metadata: HashMap<String, serde_json::Value>,
}

	/// Metadata about a signing key for rotation tracking
	#[derive(Debug, Clone, Serialize, Deserialize)]
	pub struct KeyMetadata {
		/// Hash of public key for identification
		pub key_id: String,
		/// Key version for rotation
		pub version: u32,
		/// When this key was created
		pub created_at: chrono::DateTime<chrono::Utc>,
		/// Optional expiration
		pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
		/// Optional predecessor key_id for rotation chain
		pub predecessor_key_id: Option<String>,
	}

	/// List of revoked keys
	#[derive(Debug, Clone, Serialize, Deserialize)]
	pub struct RevocationList {
		/// Revoked key_ids
		pub revoked_keys: Vec<String>,
		/// When the list was published
		pub timestamp: chrono::DateTime<chrono::Utc>,
	}

impl Manifest {
    /// Create a new manifest
    pub fn new(
        bundle_root_hash: String,
        proof_count: usize,
        public_key: String,
        parent_manifest_id: Option<String>,
    ) -> Self {
        // Derive manifest_id deterministically from bundle content
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        bundle_root_hash.hash(&mut hasher);
        let h1 = hasher.finish();
        let mut hasher2 = DefaultHasher::new();
        public_key.hash(&mut hasher2);
        let h2 = hasher2.finish();
        let manifest_id = format!("{:016x}-{:016x}", h1, h2);

        Self {
            schema_version: crate::SCHEMA_VERSION.to_string(),
            engine_version: crate::MKPE_VERSION.to_string(),
            manifest_id,
            system_fingerprint: SystemFingerprint::capture(),
            bundle_root_hash,
            proof_count,
            sealed_timestamp: chrono::Utc::now(),
            verifier_public_key: public_key,
			signature: String::new(), // Will be set after signing
			parent_manifest_id,
			nonce: None,
			metadata: HashMap::new(),
		}
    }

	/// Sign this manifest with a keypair
	pub fn sign(&mut self, keypair: &dyn crate::crypto::Signer) -> Result<()> {
        // Sign only the stable identity fields for deterministic signatures
        let manifest_data = serde_json::json!({
            "schema_version": self.schema_version,
            "engine_version": self.engine_version,
            "manifest_id": self.manifest_id,
            "bundle_root_hash": self.bundle_root_hash,
            "proof_count": self.proof_count,
            "verifier_public_key": self.verifier_public_key,
			"verifier_public_key": self.verifier_public_key,
			"parent_manifest_id": self.parent_manifest_id,
			"nonce": self.nonce,
			"metadata": self.metadata,
		});
        let canonical = serde_json::to_string(&manifest_data)
            .map_err(|e| crate::MkpeError::BundleError(format!("Manifest serialization failed: {}", e)))?;
        self.signature = keypair.sign(canonical.as_bytes())?;
        Ok(())
    }

    /// Verify this manifest's signature
    pub fn verify(&self) -> Result<bool> {
        // Same canonical JSON as sign() - stable identity fields only
        let manifest_data = serde_json::json!({
            "schema_version": self.schema_version,
            "engine_version": self.engine_version,
            "manifest_id": self.manifest_id,
            "bundle_root_hash": self.bundle_root_hash,
            "proof_count": self.proof_count,
            "verifier_public_key": self.verifier_public_key,
			"verifier_public_key": self.verifier_public_key,
			"parent_manifest_id": self.parent_manifest_id,
			"nonce": self.nonce,
			"metadata": self.metadata,
		});
        let canonical = serde_json::to_string(&manifest_data)
            .map_err(|e| crate::MkpeError::BundleError(format!("Manifest serialization failed: {}", e)))?;
        crate::crypto::verify_signature(
            &self.verifier_public_key,
            canonical.as_bytes(),
            &self.signature,
        )
    }

    /// Add custom metadata
    pub fn add_metadata(&mut self, key: String, value: serde_json::Value) {
        self.metadata.insert(key, value);
    }

    /// Get canonical hash of this manifest
    pub fn canonical_hash(&self) -> String {
        use sha2::{Digest, Sha256};

        let manifest_json = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(manifest_json.as_bytes());
        hex::encode(hasher.finalize())
    }

	/// Verify nonce is at least the expected minimum
	pub fn verify_nonce(&self, expected: u64) -> bool {
		self.nonce.map(|n| n >= expected).unwrap_or(false)
	}

	/// Check if this is a genesis manifest (no parent)
	pub fn is_genesis(&self) -> bool {
		self.parent_manifest_id.is_none()
	}

	/// Compute chain depth from metadata or infer from parent presence
	pub fn chain_depth(&self) -> u32 {
		self.metadata
			.get("chain_depth")
			.and_then(|v| v.as_u64())
			.map(|d| d as u32)
			.or_else(|| if self.parent_manifest_id.is_some() { Some(2) } else { Some(1) })
			.unwrap_or(1)
	}

	/// Verify key metadata against a trusted key set and optional revocation list
	pub fn verify_key_rotation(
		&self,
		trusted_keys: &std::collections::BTreeSet<String>,
		revocation_list: Option<&RevocationList>,
	) -> Result<bool> {
		if !trusted_keys.contains(&self.verifier_public_key) {
			return Err(crate::MkpeError::VerificationFailed(
				"Signing key is not in trusted key set".into(),
			));
		}

		if let Some(rl) = revocation_list {
			if rl.revoked_keys.contains(&self.verifier_public_key) {
				return Ok(false);
			}
		}

		Ok(true)
	}
}

/// Build information embedded in the engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    pub version: String,
    pub build_timestamp: String,
    pub compiler: String,
    pub target_triple: String,
    pub features: Vec<String>,
}

impl BuildInfo {
    /// Create build info from compile-time environment
    pub fn compile_time() -> Self {
        Self {
            version: crate::MKPE_VERSION.to_string(),
            build_timestamp: chrono::Utc::now().to_rfc3339(),
            compiler: std::env!("CARGO_PKG_RUST_VERSION").to_string(),
            target_triple: std::env::consts::ARCH.to_string(),
            features: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_creation() {
        let manifest = Manifest::new(
            "test_root_hash".to_string(),
            5,
            "test_public_key".to_string(),
            None,
        );

        assert_eq!(manifest.schema_version, crate::SCHEMA_VERSION);
        assert_eq!(manifest.proof_count, 5);
        assert!(!manifest.manifest_id.is_empty());
    }

    #[test]
    fn test_manifest_signing() -> Result<()> {
        let keypair = crate::crypto::generate_keypair();
        let mut manifest = Manifest::new(
            "test_root_hash".to_string(),
            3,
            keypair.public_key.clone(),
            None,
        );

        manifest.sign(&keypair)?;
        assert!(!manifest.signature.is_empty());

        let is_valid = manifest.verify()?;
        assert!(is_valid);

        Ok(())
    }

    #[test]
    fn test_system_fingerprint() {
        let fingerprint = SystemFingerprint::capture();
        assert!(!fingerprint.user.is_empty());
        assert!(!fingerprint.platform.is_empty());
        assert!(!fingerprint.hostname.is_empty());
        assert!(fingerprint.process_id > 0);
    }
}
