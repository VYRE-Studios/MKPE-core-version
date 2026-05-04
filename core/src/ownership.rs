//! Ownership transfer protocol for MKPE
//!
//! Provides `TransferManifest`, `RevocationEntry`, and `OwnershipChain`
//! for proving and transferring ownership of digital creations in a
//! marketplace or provenance tracking system.
//!
//! # Concepts
//! - **Genesis manifest**: The first creation record with no parent.
//! - **Transfer manifest**: A multi-party signed document that records a
//!   transfer of ownership from one key to another.
//! - **Ownership chain**: A linked sequence of transfer manifests starting
//!   from the genesis record.
//! - **Revocation**: A signed statement that invalidates a transfer
//!   manifest, breaking the ownership chain.

use crate::{crypto::verify_signature, error::MkpeError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Commercial or licensing terms attached to a transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferTerms {
    /// Price as an opaque string (e.g. "1.5", "100")
    pub price: Option<String>,
    /// Currency or token identifier (e.g. "ETH", "USD", "MKPE_CREDIT")
    pub currency: Option<String>,
    /// Creator royalty percentage on future resales (0-100).
    pub royalty_percentage: Option<u8>,
    /// Maximum number of times this asset may be resold.
    pub max_resale_count: Option<u32>,
    /// Arbitrary custom terms.
    pub custom: HashMap<String, serde_json::Value>,
}

impl Default for TransferTerms {
    fn default() -> Self {
        Self {
            price: None,
            currency: None,
            royalty_percentage: None,
            max_resale_count: None,
            custom: HashMap::new(),
        }
    }
}

/// Lifecycle status of a transfer manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransferStatus {
    /// Created but not yet fully signed.
    Proposed,
    /// All required signatures collected and the transfer is valid.
    Executed,
    /// Invalidated by a revocation record.
    Revoked,
}

/// A single signature on a transfer manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEntry {
    /// Key identifier of the signer.
    pub key_id: String,
    /// Base64-encoded Ed25519 signature.
    pub signature: String,
    /// UTC timestamp when the signature was produced.
    pub timestamp: DateTime<Utc>,
}

/// A manifest documenting a transfer of ownership for a digital asset.
///
/// # Usage
/// 1. The seller creates a `TransferManifest` with `from_key_id` set to
///    themselves, `to_key_id` set to the buyer, and
///    `required_signers` listing all parties that must sign.
/// 2. Each party signs the canonical JSON of the manifest and appends
///    a [`SignatureEntry`].
/// 3. Once all required signatures are present, the manifest is
///    `Executed`.
/// 4. The manifest is stored as the next link in the ownership chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferManifest {
    /// MKPE schema version.
    pub schema_version: String,
    /// Engine version that created this manifest.
    pub engine_version: String,
    /// Globally unique identifier for this transfer manifest.
    pub transfer_id: String,
    /// Globally unique identifier for the asset being transferred.
    pub asset_id: String,
    /// Previous manifest in the ownership chain (None for genesis).
    pub previous_manifest_id: Option<String>,
    /// Key ID of the current owner (seller).
    pub from_key_id: String,
    /// Key ID of the new owner (buyer).
    pub to_key_id: String,
    /// Optional key ID of the marketplace or escrow agent.
    pub marketplace_key_id: Option<String>,
    /// Monotonic nonce for replay protection.
    pub nonce: u64,
    /// When the manifest was created.
    pub timestamp: DateTime<Utc>,
    /// Commercial or licensing terms.
    pub terms: TransferTerms,
    /// Required key IDs that must sign before the transfer is valid.
    pub required_signers: Vec<String>,
    /// Collected signatures.
    pub signatures: Vec<SignatureEntry>,
    /// Current lifecycle status.
    pub status: TransferStatus,
    /// Arbitrary metadata.
    pub metadata: HashMap<String, serde_json::Value>,
}

impl TransferManifest {
    /// Create a new transfer manifest.
    ///
    /// `required_signers` should include the seller (`from_key_id`), the
    /// buyer (`to_key_id`), and optionally the marketplace agent.
    pub fn new(
        asset_id: String,
        previous_manifest_id: Option<String>,
        from_key_id: String,
        to_key_id: String,
        marketplace_key_id: Option<String>,
        nonce: u64,
        terms: TransferTerms,
        required_signers: Vec<String>,
    ) -> Self {
        let transfer_id = compute_transfer_id(
            &asset_id,
            &previous_manifest_id,
            &from_key_id,
            &to_key_id,
            nonce,
        );

        Self {
            schema_version: crate::SCHEMA_VERSION.to_string(),
            engine_version: crate::MKPE_VERSION.to_string(),
            transfer_id,
            asset_id,
            previous_manifest_id,
            from_key_id,
            to_key_id,
            marketplace_key_id,
            nonce,
            timestamp: Utc::now(),
            terms,
            required_signers,
            signatures: Vec::new(),
            status: TransferStatus::Proposed,
            metadata: HashMap::new(),
        }
    }

    /// Return canonical JSON bytes that must be signed.
    fn canonical(&self) -> Result<Vec<u8>> {
        let payload = serde_json::json!({
            "schema_version": self.schema_version,
            "engine_version": self.engine_version,
            "transfer_id": self.transfer_id,
            "asset_id": self.asset_id,
            "previous_manifest_id": self.previous_manifest_id,
            "from_key_id": self.from_key_id,
            "to_key_id": self.to_key_id,
            "marketplace_key_id": self.marketplace_key_id,
            "nonce": self.nonce,
            "terms": self.terms,
            "required_signers": self.required_signers,
            "metadata": self.metadata,
        });
        serde_json::to_vec(&payload)
            .map_err(|e| MkpeError::ManifestError(format!("Canonical JSON failed: {}", e)))
    }

    /// Sign this manifest with a keypair.
    ///
    /// The caller must provide the matching `key_id` so the signature is
    /// correctly attributed.
    pub fn sign(
        &mut self,
        keypair: &dyn crate::crypto::Signer,
    ) -> Result<()> {
        let canonical = self.canonical()?;
        let sig = keypair.sign(&canonical)?;
        self.signatures.push(SignatureEntry {
            key_id: keypair.key_id(),
            signature: sig,
            timestamp: Utc::now(),
        });

        // Auto-promote to Executed if all required signers have now signed.
        if self.can_execute() {
            self.status = TransferStatus::Executed;
        }

        Ok(())
    }

    /// Verify that every signature in `signatures` is valid and from a
    /// distinct signer.
    ///
    /// Returns `Ok(true)` only if every signature verifies against its
    /// claimed `key_id` using the provided `public_keys` map.
    pub fn verify_signatures(
        &self,
        public_keys: &HashMap<String, String>,
    ) -> Result<bool> {
        let canonical = self.canonical()?;

        let mut seen = std::collections::HashSet::new();
        for entry in &self.signatures {
            if !seen.insert(&entry.key_id) {
                return Ok(false); // duplicate signer
            }

            let pubkey = match public_keys.get(&entry.key_id) {
                Some(pk) => pk,
                None => return Ok(false), // unknown signer
            };

            if !verify_signature(pubkey, &canonical, &entry.signature)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Check whether all required signers have provided valid signatures.
    ///
    /// This does **not** verify the signatures cryptographically; call
    /// [`verify_signatures`] first.
    pub fn can_execute(&self) -> bool {
        let signed_ids: std::collections::HashSet<_> =
            self.signatures.iter().map(|s| &s.key_id).collect();
        self.required_signers
            .iter()
            .all(|id| signed_ids.contains(id))
    }

    /// Check if this manifest has been fully signed and is not revoked.
    pub fn is_valid(&self) -> bool {
        self.status == TransferStatus::Executed && self.can_execute()
    }

    /// Add a metadata key/value pair.
    pub fn add_metadata(&mut self, key: String, value: serde_json::Value) {
        self.metadata.insert(key, value);
    }
}

/// A signed revocation record that invalidates a transfer manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// The transfer manifest being revoked.
    pub target_transfer_id: String,
    /// Key ID of the revoking authority.
    pub revoked_by: String,
    /// Human-readable reason.
    pub reason: String,
    /// When the revocation was issued.
    pub timestamp: DateTime<Utc>,
    /// Base64-encoded Ed25519 signature over the canonical revocation
    /// payload by `revoked_by`.
    pub revocation_signature: String,
}

impl RevocationEntry {
    /// Create and sign a revocation entry.
    pub fn new(
        target_transfer_id: String,
        reason: String,
        keypair: &dyn crate::crypto::Signer,
    ) -> Result<Self> {
        let payload = canonical_revocation_payload(
            &target_transfer_id,
            &keypair.key_id(),
            &reason,
        );
        let sig = keypair.sign(&payload)?;

        Ok(Self {
            target_transfer_id,
            revoked_by: keypair.key_id(),
            reason,
            timestamp: Utc::now(),
            revocation_signature: sig,
        })
    }

    /// Verify the revocation signature against the revoker's public key.
    pub fn verify(&self, revoked_by_public_key: &str) -> Result<bool> {
        let payload = canonical_revocation_payload(
            &self.target_transfer_id,
            &self.revoked_by,
            &self.reason,
        );
        verify_signature(revoked_by_public_key, &payload, &self.revocation_signature)
    }
}

fn canonical_revocation_payload(
    target_transfer_id: &str,
    revoked_by: &str,
    reason: &str,
) -> Vec<u8> {
    let json = serde_json::json!({
        "target_transfer_id": target_transfer_id,
        "revoked_by": revoked_by,
        "reason": reason,
    });
    serde_json::to_vec(&json).unwrap_or_default()
}

/// A verified chain of ownership from genesis to the present.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipChain {
    /// The asset this chain describes.
    pub asset_id: String,
    /// The genesis manifest ID (or asset creation record).
    pub genesis_id: String,
    /// Ordered list of transfer manifests from oldest to newest.
    pub transfers: Vec<TransferManifest>,
    /// Known revocation entries keyed by target transfer ID.
    pub revocations: HashMap<String, RevocationEntry>,
}

impl OwnershipChain {
    /// Create a chain anchored at a genesis manifest.
    pub fn new(asset_id: String, genesis_id: String) -> Self {
        Self {
            asset_id,
            genesis_id,
            transfers: Vec::new(),
            revocations: HashMap::new(),
        }
    }

    /// Append a transfer manifest after verifying its integrity.
    ///
    /// Checks:
    /// 1. `asset_id` matches the chain.
    /// 2. `previous_manifest_id` links to the last transfer or genesis.
    /// 3. The manifest is `Executed` and fully signed.
    /// 4. The manifest is not revoked.
    /// 5. Signatures are cryptographically valid.
    pub fn append(
        &mut self,
        manifest: TransferManifest,
        public_keys: &HashMap<String, String>,
    ) -> Result<()> {
        if manifest.asset_id != self.asset_id {
            return Err(MkpeError::ManifestError(format!(
                "Asset ID mismatch: expected {}, got {}",
                self.asset_id, manifest.asset_id
            )));
        }

        let expected_previous = self
            .transfers
            .last()
            .map(|t| t.transfer_id.clone())
            .unwrap_or_else(|| self.genesis_id.clone());

        if manifest.previous_manifest_id.as_ref() != Some(&expected_previous) {
            return Err(MkpeError::ManifestError(format!(
                "Chain break: expected previous {}, got {:?}",
                expected_previous, manifest.previous_manifest_id
            )));
        }

        if !manifest.is_valid() {
            return Err(MkpeError::ManifestError(
                "Transfer manifest is not executed or missing required signatures".to_string(),
            ));
        }

        if self.revocations.contains_key(&manifest.transfer_id) {
            return Err(MkpeError::ManifestError(
                "Cannot append a revoked transfer manifest".to_string(),
            ));
        }

        if !manifest.verify_signatures(public_keys)? {
            return Err(MkpeError::ManifestError(
                "Signature verification failed for transfer manifest".to_string(),
            ));
        }

        self.transfers.push(manifest);
        Ok(())
    }

    /// Revoke a transfer by its ID.
    ///
    /// If the target is already in the chain, the chain is considered
    /// broken from that point onward; later transfers are not removed
    /// but the chain will report `is_valid() == false`.
    pub fn revoke(
        &mut self,
        revocation: RevocationEntry,
        revoked_by_public_key: &str,
    ) -> Result<()> {
        if !revocation.verify(revoked_by_public_key)? {
            return Err(MkpeError::ManifestError(
                "Revocation signature invalid".to_string(),
            ));
        }

        self.revocations
            .insert(revocation.target_transfer_id.clone(), revocation);
        Ok(())
    }

    /// Return the key ID of the current owner, or `None` if the chain
    /// is empty.
    pub fn current_owner(&self) -> Option<&str> {
        self.transfers.last().map(|t| t.to_key_id.as_str())
    }

    /// Check whether the chain is unbroken and no transfer is revoked.
    pub fn is_valid(&self) -> bool {
        if self.transfers.is_empty() {
            return true; // genesis-only chain is valid
        }

        for transfer in &self.transfers {
            if self.revocations.contains_key(&transfer.transfer_id) {
                return false;
            }
            if transfer.status != TransferStatus::Executed {
                return false;
            }
        }
        true
    }

    /// Number of transfers in the chain.
    pub fn transfer_count(&self) -> usize {
        self.transfers.len()
    }

    /// Check if the asset has been resold more than `max` times.
    pub fn exceeds_resale_limit(&self, max: u32) -> bool {
        self.transfers.len() as u32 > max
    }
}

/// Compute a deterministic transfer ID from the core fields.
fn compute_transfer_id(
    asset_id: &str,
    previous_manifest_id: &Option<String>,
    from_key_id: &str,
    to_key_id: &str,
    nonce: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(asset_id.as_bytes());
    if let Some(prev) = previous_manifest_id {
        hasher.update(prev.as_bytes());
    }
    hasher.update(from_key_id.as_bytes());
    hasher.update(to_key_id.as_bytes());
    hasher.update(&nonce.to_le_bytes());
    hex::encode(&hasher.finalize()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;

    fn key_map(keypair: &dyn crate::crypto::Signer) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(keypair.key_id(), keypair.public_key().expect("public key"));
        m
    }

    fn three_parties() -> (crate::crypto::KeyPair, crate::crypto::KeyPair, crate::crypto::KeyPair) {
        (generate_keypair(), generate_keypair(), generate_keypair())
    }

    #[test]
    fn test_transfer_manifest_id_is_deterministic() {
        let id1 = compute_transfer_id("asset-1", &None, "alice", "bob", 42);
        let id2 = compute_transfer_id("asset-1", &None, "alice", "bob", 42);
        let id3 = compute_transfer_id("asset-1", &None, "alice", "bob", 43);
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_transfer_manifest_creation_and_signing() {
        let (alice, bob, _market) = three_parties();
        let mut manifest = TransferManifest::new(
            "asset-1".to_string(),
            None,
            alice.key_id.clone(),
            bob.key_id.clone(),
            None,
            1,
            TransferTerms::default(),
            vec![alice.key_id.clone(), bob.key_id.clone()],
        );

        assert_eq!(manifest.status, TransferStatus::Proposed);
        assert!(!manifest.can_execute());

        // Alice signs
        manifest.sign(&alice).unwrap();
        assert_eq!(manifest.status, TransferStatus::Proposed); // still missing Bob
        assert!(!manifest.can_execute());

        // Bob signs
        manifest.sign(&bob).unwrap();
        assert_eq!(manifest.status, TransferStatus::Executed);
        assert!(manifest.can_execute());
        assert!(manifest.is_valid());

        let public_keys = {
            let mut m = HashMap::new();
            m.insert(alice.key_id.clone(), alice.public_key.clone());
            m.insert(bob.key_id.clone(), bob.public_key.clone());
            m
        };
        assert!(manifest.verify_signatures(&public_keys).unwrap());
    }

    #[test]
    fn test_transfer_missing_required_signer_fails_execution() {
        let (alice, bob, _market) = three_parties();
        let mut manifest = TransferManifest::new(
            "asset-1".to_string(),
            None,
            alice.key_id.clone(),
            bob.key_id.clone(),
            None,
            1,
            TransferTerms::default(),
            vec![alice.key_id.clone(), bob.key_id.clone()],
        );

        // Only Alice signs
        manifest.sign(&alice).unwrap();
        assert!(!manifest.can_execute());
        assert!(!manifest.is_valid());
    }

    #[test]
    fn test_transfer_duplicate_signer_does_not_count_twice() {
        let (alice, _bob, _market) = three_parties();
        let mut manifest = TransferManifest::new(
            "asset-1".to_string(),
            None,
            alice.key_id.clone(),
            "other".to_string(),
            None,
            1,
            TransferTerms::default(),
            vec![alice.key_id.clone(), "other".to_string()],
        );

        manifest.sign(&alice).unwrap();
        manifest.sign(&alice).unwrap(); // duplicate

        let mut public_keys = key_map(&alice);
        // `other` public key not present, so verify should fail because
        // required signer "other" is missing.
        assert!(!manifest.verify_signatures(&public_keys).unwrap());
    }

    #[test]
    fn test_transfer_signature_verification_with_wrong_key_fails() {
        let (alice, bob, eve) = three_parties();
        let mut manifest = TransferManifest::new(
            "asset-1".to_string(),
            None,
            alice.key_id.clone(),
            bob.key_id.clone(),
            None,
            1,
            TransferTerms::default(),
            vec![alice.key_id.clone()],
        );

        manifest.sign(&alice).unwrap();

        // Verify with Eve's public key instead of Alice's
        let mut public_keys = HashMap::new();
        public_keys.insert(alice.key_id.clone(), eve.public_key.clone());
        assert!(!manifest.verify_signatures(&public_keys).unwrap());
    }

    #[test]
    fn test_ownership_chain_append_and_current_owner() {
        let (alice, bob, carol) = three_parties();

        let mut chain = OwnershipChain::new("asset-1".to_string(), "genesis-0".to_string());
        assert_eq!(chain.current_owner(), None);
        assert!(chain.is_valid());

        // First transfer: Alice -> Bob
        let mut t1 = TransferManifest::new(
            "asset-1".to_string(),
            Some("genesis-0".to_string()),
            alice.key_id.clone(),
            bob.key_id.clone(),
            None,
            1,
            TransferTerms::default(),
            vec![alice.key_id.clone(), bob.key_id.clone()],
        );
        t1.sign(&alice).unwrap();
        t1.sign(&bob).unwrap();

        let mut public_keys = HashMap::new();
        public_keys.insert(alice.key_id.clone(), alice.public_key.clone());
        public_keys.insert(bob.key_id.clone(), bob.public_key.clone());

        chain.append(t1, &public_keys).unwrap();
        assert_eq!(chain.current_owner(), Some(bob.key_id.as_str()));
        assert_eq!(chain.transfer_count(), 1);
        assert!(chain.is_valid());

        // Second transfer: Bob -> Carol
        let mut t2 = TransferManifest::new(
            "asset-1".to_string(),
            Some(chain.transfers.last().unwrap().transfer_id.clone()),
            bob.key_id.clone(),
            carol.key_id.clone(),
            None,
            2,
            TransferTerms::default(),
            vec![bob.key_id.clone(), carol.key_id.clone()],
        );
        t2.sign(&bob).unwrap();
        t2.sign(&carol).unwrap();

        public_keys.insert(carol.key_id.clone(), carol.public_key.clone());
        chain.append(t2, &public_keys).unwrap();
        assert_eq!(chain.current_owner(), Some(carol.key_id.as_str()));
        assert_eq!(chain.transfer_count(), 2);
        assert!(chain.is_valid());
    }

    #[test]
    fn test_ownership_chain_rejects_broken_link() {
        let (alice, bob, _carol) = three_parties();
        let mut chain = OwnershipChain::new("asset-1".to_string(), "genesis-0".to_string());

        let mut t1 = TransferManifest::new(
            "asset-1".to_string(),
            Some("genesis-0".to_string()),
            alice.key_id.clone(),
            bob.key_id.clone(),
            None,
            1,
            TransferTerms::default(),
            vec![alice.key_id.clone(), bob.key_id.clone()],
        );
        t1.sign(&alice).unwrap();
        t1.sign(&bob).unwrap();

        let mut public_keys = HashMap::new();
        public_keys.insert(alice.key_id.clone(), alice.public_key.clone());
        public_keys.insert(bob.key_id.clone(), bob.public_key.clone());
        chain.append(t1, &public_keys).unwrap();

        // Try to append a manifest that points to the wrong previous ID
        let mut t2 = TransferManifest::new(
            "asset-1".to_string(),
            Some("wrong-previous".to_string()),
            bob.key_id.clone(),
            alice.key_id.clone(),
            None,
            2,
            TransferTerms::default(),
            vec![bob.key_id.clone(), alice.key_id.clone()],
        );
        t2.sign(&bob).unwrap();
        t2.sign(&alice).unwrap();

        let err = chain.append(t2, &public_keys).unwrap_err();
        assert!(format!("{}", err).contains("Chain break"));
    }

    #[test]
    fn test_ownership_chain_rejects_wrong_asset_id() {
        let (alice, bob, _carol) = three_parties();
        let mut chain = OwnershipChain::new("asset-1".to_string(), "genesis-0".to_string());

        let mut t1 = TransferManifest::new(
            "asset-2".to_string(), // wrong asset
            Some("genesis-0".to_string()),
            alice.key_id.clone(),
            bob.key_id.clone(),
            None,
            1,
            TransferTerms::default(),
            vec![alice.key_id.clone(), bob.key_id.clone()],
        );
        t1.sign(&alice).unwrap();
        t1.sign(&bob).unwrap();

        let mut public_keys = HashMap::new();
        public_keys.insert(alice.key_id.clone(), alice.public_key.clone());
        public_keys.insert(bob.key_id.clone(), bob.public_key.clone());

        let err = chain.append(t1, &public_keys).unwrap_err();
        assert!(format!("{}", err).contains("Asset ID mismatch"));
    }

    #[test]
    fn test_ownership_chain_rejects_non_executed_manifest() {
        let (alice, bob, _carol) = three_parties();
        let mut chain = OwnershipChain::new("asset-1".to_string(), "genesis-0".to_string());

        let mut t1 = TransferManifest::new(
            "asset-1".to_string(),
            Some("genesis-0".to_string()),
            alice.key_id.clone(),
            bob.key_id.clone(),
            None,
            1,
            TransferTerms::default(),
            vec![alice.key_id.clone(), bob.key_id.clone()],
        );
        t1.sign(&alice).unwrap(); // missing Bob

        let mut public_keys = HashMap::new();
        public_keys.insert(alice.key_id.clone(), alice.public_key.clone());
        public_keys.insert(bob.key_id.clone(), bob.public_key.clone());

        let err = chain.append(t1, &public_keys).unwrap_err();
        assert!(format!("{}", err).contains("not executed"));
    }

    #[test]
    fn test_revocation_breaks_chain_validity() {
        let (alice, bob, carol) = three_parties();
        let mut chain = OwnershipChain::new("asset-1".to_string(), "genesis-0".to_string());

        let mut t1 = TransferManifest::new(
            "asset-1".to_string(),
            Some("genesis-0".to_string()),
            alice.key_id.clone(),
            bob.key_id.clone(),
            None,
            1,
            TransferTerms::default(),
            vec![alice.key_id.clone(), bob.key_id.clone()],
        );
        t1.sign(&alice).unwrap();
        t1.sign(&bob).unwrap();

        let mut public_keys = HashMap::new();
        public_keys.insert(alice.key_id.clone(), alice.public_key.clone());
        public_keys.insert(bob.key_id.clone(), bob.public_key.clone());

        chain.append(t1, &public_keys).unwrap();
        assert!(chain.is_valid());

        // Create a revocation signed by the original owner (Alice)
        let transfer_id = chain.transfers[0].transfer_id.clone();
        let revocation = RevocationEntry::new(
            transfer_id.clone(),
            "Stolen account".to_string(),
            &alice,
        )
        .unwrap();

        chain.revoke(revocation, &alice.public_key).unwrap();
        assert!(!chain.is_valid());
    }

    #[test]
    fn test_revocation_with_wrong_key_fails() {
        let (alice, _bob, eve) = three_parties();
        let revocation = RevocationEntry::new(
            "tx-123".to_string(),
            "Malicious revocation".to_string(),
            &eve,
        )
        .unwrap();

        // Try to verify with Alice's public key instead of Eve's
        assert!(!revocation.verify(&alice.public_key).unwrap());
    }

    #[test]
    fn test_resale_limit_enforcement() {
        let mut chain = OwnershipChain::new("asset-1".to_string(), "genesis-0".to_string());
        // Append 5 transfers by bypassing validation for this unit test
        for i in 0..5 {
            chain.transfers.push(TransferManifest::new(
                "asset-1".to_string(),
                None,
                format!("seller-{}", i),
                format!("buyer-{}", i),
                None,
                i as u64,
                TransferTerms::default(),
                vec![format!("seller-{}", i)],
            ));
        }
        assert_eq!(chain.transfer_count(), 5);
        assert!(chain.exceeds_resale_limit(3));
        assert!(!chain.exceeds_resale_limit(5));
    }

    #[test]
    fn test_terms_royalty_percentage_roundtrip() {
        let terms = TransferTerms {
            price: Some("10.5".to_string()),
            currency: Some("ETH".to_string()),
            royalty_percentage: Some(10),
            max_resale_count: Some(3),
            custom: {
                let mut m = HashMap::new();
                m.insert("license".to_string(), serde_json::json!("CC-BY-4.0"));
                m
            },
        };
        let json = serde_json::to_string(&terms).unwrap();
        let decoded: TransferTerms = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.price, terms.price);
        assert_eq!(decoded.currency, terms.currency);
        assert_eq!(decoded.royalty_percentage, terms.royalty_percentage);
        assert_eq!(decoded.max_resale_count, terms.max_resale_count);
        assert_eq!(decoded.custom.get("license"), Some(&serde_json::json!("CC-BY-4.0")));
    }
}
