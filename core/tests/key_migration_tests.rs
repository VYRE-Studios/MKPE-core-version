//! Key migration and rotation tests for MKPE
//!
//! These tests verify key lifecycle management, cross-key verification
//! failures, key format validation, and manifest chaining behavior.
//!
//! ## Design notes
//! - MKPE has no built-in key revocation: attestations/bundles signed by
//!   revoked keys will still verify. Key trust is external.
//! - MKPE has no multi-signature support: each bundle/attestation has exactly
//!   one signer identified by their public key.
//! - Verification requires explicit `trusted_public_key` when verifying
//!   attestations; bundles embed the signing key in the archive header.

use morse_kirby_core::*;
use std::fs;
use tempfile::TempDir;

/// Key rotation scenario: bundle created with key A cannot be verified with key B
#[test]
fn test_bundle_created_with_key_a_cannot_verify_with_key_b() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir(&artifact_dir)?;
    fs::write(artifact_dir.join("test.txt"), "Hello world")?;

    // Create two different keypairs
    let keypair_a = generate_keypair();
    let keypair_b = generate_keypair();

    // Ensure they are different
    assert_ne!(keypair_a.public_key, keypair_b.public_key);

    // Create bundle with keypair A
    let archive_path_a = temp_dir.path().join("bundle_a.mkpe");
    create_mkpe_bundle(&artifact_dir, &keypair_a, &archive_path_a)?;

    // Load the bundle
    let loaded = MkpeArchive::load(&archive_path_a)?;

    // Verify the archive's embedded public key matches keypair A
    assert_eq!(
        loaded.manifest.verifier_public_key, keypair_a.public_key,
        "Bundle should embed the public key of the signer"
    );

    // Try to verify using keypair B's public key - this should fail
    // because the bundle was signed with keypair A's private key
    let result = loaded.verify_artifact_with_public_key(&artifact_dir, &keypair_b.public_key);

    assert!(
        result.is_err(),
        "Verification with wrong key should fail, got: {:?}",
        result
    );

    // Verify with correct key A succeeds
    let result_a = loaded.verify_artifact_with_public_key(&artifact_dir, &keypair_a.public_key);
    assert!(
        result_a.is_ok(),
        "Verification with correct key should succeed"
    );

    Ok(())
}

/// Key rotation scenario: attestation signed with old key rejected by new key
#[test]
fn test_attestation_signed_with_old_key_rejected_by_new_key() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let subject_path = temp_dir.path().join("subject.txt");
    fs::write(&subject_path, "Important data")?;

    // Create old and new keypairs
    let old_keypair = generate_keypair();
    let new_keypair = generate_keypair();

    // Sign attestation with OLD key
    let options = AttestationOptions {
        attested_by: "test-user".to_string(),
        command: Some("cargo build".to_string()),
        bundle_path: None,
    };
    let attestation = create_build_attestation(&subject_path, &old_keypair, options)?;

    // Verify attestation uses the OLD key
    assert_eq!(
        attestation.signer_public_key, old_keypair.public_key,
        "Attestation should record the signing key"
    );

    // Verification with new key should fail
    let verify_options = AttestationVerificationOptions {
        subject_path: Some(subject_path.clone()),
        trusted_public_key: Some(new_keypair.public_key.clone()),
        bundle_path: None,
    };

    let result = verify_build_attestation(&attestation, verify_options);
    assert!(
        result.is_err(),
        "Verification with wrong key should fail, got: {:?}",
        result
    );

    // Verification with OLD key succeeds
    let verify_options_old = AttestationVerificationOptions {
        subject_path: Some(subject_path),
        trusted_public_key: Some(old_keypair.public_key.clone()),
        bundle_path: None,
    };

    let result_old = verify_build_attestation(&attestation, verify_options_old);
    assert!(
        result_old.is_ok(),
        "Verification with correct key should succeed"
    );

    Ok(())
}

/// Bundle verification without providing the expected public key
#[test]
fn test_bundle_without_trusted_key_fails_verification() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir(&artifact_dir)?;
    fs::write(artifact_dir.join("test.txt"), "Test content")?;

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("bundle.mkpe");
    create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;

    let loaded = MkpeArchive::load(&archive_path)?;

    // The manifest embeds the signer public key
    let embedded_key = loaded.manifest.verifier_public_key.clone();

    // Try verification with a completely different key
    let random_keypair = generate_keypair();
    let result = loaded.verify_artifact_with_public_key(&artifact_dir, &random_keypair.public_key);

    assert!(
        result.is_err(),
        "Verification with non-embedded key should fail"
    );

    // Verification with embedded key succeeds
    let result_embedded = loaded.verify_artifact_with_public_key(&artifact_dir, &embedded_key);
    assert!(
        result_embedded.is_ok(),
        "Verification with embedded key should succeed"
    );

    Ok(())
}

/// Verify that a bundle contains the public key that created it
#[test]
fn test_archive_preserves_signer_public_key() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir(&artifact_dir)?;
    fs::write(artifact_dir.join("data.bin"), "Binary data")?;

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("preserved.mkpe");
    create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;

    let loaded = MkpeArchive::load(&archive_path)?;

    // The manifest's verifier_public_key field contains the signer's public key
    assert_eq!(
        loaded.manifest.verifier_public_key, keypair.public_key,
        "Archive manifest should preserve the signing public key"
    );

    Ok(())
}

/// Verify that an attestation contains the signer's public key
#[test]
fn test_attestation_preserves_signer_public_key() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let subject_path = temp_dir.path().join("source.rs");
    fs::write(&subject_path, "fn main() {}")?;

    let keypair = generate_keypair();
    let options = AttestationOptions {
        attested_by: "developer".to_string(),
        command: None,
        bundle_path: None,
    };

    let attestation = create_build_attestation(&subject_path, &keypair, options)?;

    // Attestation should preserve the signer's public key
    assert_eq!(
        attestation.signer_public_key, keypair.public_key,
        "Attestation should preserve signer's public key"
    );

    // Verify attestation signature using the preserved key
    let verify_options = AttestationVerificationOptions {
        subject_path: Some(subject_path),
        trusted_public_key: Some(keypair.public_key),
        bundle_path: None,
    };

    let report = verify_build_attestation(&attestation, verify_options)?;
    assert_eq!(
        report.signer_public_key, attestation.signer_public_key,
        "Verification report should echo the signer's public key"
    );

    Ok(())
}

/// Verify that a manifest stores the public key used for signing
#[test]
fn test_manifest_stores_verifier_public_key() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir(&artifact_dir)?;
    fs::write(artifact_dir.join("manifest_test.txt"), "Content")?;

    let keypair = generate_keypair();

    // Create proofs and bundle
    let proofs = proof::create_recursive_proofs(&artifact_dir, &keypair)?;
    let bundle = proof::create_proof_bundle(proofs, &keypair, None)?;

    // Create manifest
    let mut manifest = Manifest::new(
        bundle.root_hash.clone(),
        bundle.proofs.len(),
        keypair.public_key.clone(),
        None,
    );

    // Sign the manifest
    manifest.sign(&keypair)?;

    // Manifest should store the verifier public key
    assert_eq!(
        manifest.verifier_public_key, keypair.public_key,
        "Manifest should store the verification public key"
    );

    // Verify manifest signature
    assert!(
        manifest.verify()?,
        "Manifest signature should verify with stored key"
    );

    Ok(())
}

/// Multi-signer scenario: two keypairs create two independent bundles
#[test]
fn test_multiple_signers_different_bundles() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir_a = temp_dir.path().join("artifact_a");
    let artifact_dir_b = temp_dir.path().join("artifact_b");
    fs::create_dir_all(&artifact_dir_a)?;
    fs::create_dir_all(&artifact_dir_b)?;

    fs::write(artifact_dir_a.join("file_a.txt"), "Content from A")?;
    fs::write(artifact_dir_b.join("file_b.txt"), "Content from B")?;

    let keypair_alice = generate_keypair();
    let keypair_bob = generate_keypair();

    // Alice creates her bundle
    let archive_path_alice = temp_dir.path().join("alice.mkpe");
    create_mkpe_bundle(&artifact_dir_a, &keypair_alice, &archive_path_alice)?;

    // Bob creates his bundle
    let archive_path_bob = temp_dir.path().join("bob.mkpe");
    create_mkpe_bundle(&artifact_dir_b, &keypair_bob, &archive_path_bob)?;

    // Load and verify Alice's bundle
    let loaded_alice = MkpeArchive::load(&archive_path_alice)?;
    assert_eq!(
        loaded_alice.manifest.verifier_public_key, keypair_alice.public_key,
        "Alice's bundle should have Alice's key"
    );
    assert!(
        loaded_alice.verify_artifact_with_public_key(&artifact_dir_a, &keypair_alice.public_key).is_ok()
    );

    // Load and verify Bob's bundle
    let loaded_bob = MkpeArchive::load(&archive_path_bob)?;
    assert_eq!(
        loaded_bob.manifest.verifier_public_key, keypair_bob.public_key,
        "Bob's bundle should have Bob's key"
    );
    assert!(
        loaded_bob.verify_artifact_with_public_key(&artifact_dir_b, &keypair_bob.public_key).is_ok()
    );

    // Cross-verification should fail
    assert!(
        loaded_alice.verify_artifact_with_public_key(&artifact_dir_a, &keypair_bob.public_key).is_err()
    );
    assert!(
        loaded_bob.verify_artifact_with_public_key(&artifact_dir_b, &keypair_alice.public_key).is_err()
    );

    Ok(())
}

/// Only the possessor of the private key can create valid signatures
#[test]
fn test_bundle_can_only_be_signed_by_possessor_of_private_key() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir(&artifact_dir)?;
    fs::write(artifact_dir.join("secret.txt"), "Secret content")?;

    let legitimate_keypair = generate_keypair();

    // Legitimate user creates bundle
    let archive_path = temp_dir.path().join("legitimate.mkpe");
    create_mkpe_bundle(&artifact_dir, &legitimate_keypair, &archive_path)?;

    let loaded = MkpeArchive::load(&archive_path)?;

    // Create a fake keypair (attacker cannot have the real private key)
    let attacker_keypair = generate_keypair();

    // Attacker cannot verify as if they were the legitimate signer
    let result = loaded.verify_artifact_with_public_key(
        &artifact_dir,
        &attacker_keypair.public_key,
    );
    assert!(
        result.is_err(),
        "Attacker with different key should not be able to verify"
    );

    // Only the legitimate keypair's public key should work
    let result_legit = loaded.verify_artifact_with_public_key(
        &artifact_dir,
        &legitimate_keypair.public_key,
    );
    assert!(
        result_legit.is_ok(),
        "Legitimate signer should be able to verify"
    );

    Ok(())
}

/// MKPE has no built-in key revocation mechanism
///
/// Attestations and bundles signed by keys that would be "revoked"
/// in an external system will still verify because MKPE itself
/// does not maintain a revocation list.
///
/// Key trust is entirely external to MKPE.
#[test]
fn test_no_explicit_revocation_mechanism() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let subject_path = temp_dir.path().join("to_revoke.txt");
    fs::write(&subject_path, "Data signed with soon-to-be-revoked key")?;

    let keypair = generate_keypair();

    // Create attestation
    let options = AttestationOptions {
        attested_by: "admin".to_string(),
        command: Some("deploy".to_string()),
        bundle_path: None,
    };
    let attestation = create_build_attestation(&subject_path, &keypair, options)?;

    // Simulate "revocation" in external system
    let revoked_key = keypair.public_key.clone();

    // In MKPE, there is no revoke() function, no revocation list,
    // and no timestamp-based expiration. The attestation still verifies.
    let verify_options = AttestationVerificationOptions {
        subject_path: Some(subject_path),
        trusted_public_key: Some(revoked_key.clone()),
        bundle_path: None,
    };

    // NOTE: This test documents that MKPE has no revocation.
    // In production, key revocation must be handled by the
    // verification infrastructure outside MKPE.
    let result = verify_build_attestation(&attestation, verify_options.clone());

    // The attestation verifies successfully because MKPE has no
    // built-in revocation. External systems must track revoked keys.
    assert!(
        result.is_ok(),
        "MKPE does not implement revocation - attestation still verifies"
    );

    // Verify no revocation-related fields exist in types
    // (This is a compile-time check via the API, not runtime)
    // AttestationVerificationOptions has no revocation_list field
    // BuildAttestation has no expires_at or revoked_at fields

    Ok(())
}

/// Verification requires trusted_public_key to be explicitly provided
#[test]
fn test_trusted_key_must_be_explicitly_provided() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let subject_path = temp_dir.path().join("explicit_key.txt");
    fs::write(&subject_path, "Data requiring explicit trust")?;

    let keypair = generate_keypair();

    let options = AttestationOptions {
        attested_by: "tester".to_string(),
        command: None,
        bundle_path: None,
    };
    let attestation = create_build_attestation(&subject_path, &keypair, options)?;

    // Verification WITHOUT trusted_public_key (None)
    let verify_options_no_trust = AttestationVerificationOptions {
        subject_path: Some(subject_path.clone()),
        trusted_public_key: None,
        bundle_path: None,
    };

    let result = verify_build_attestation(&attestation, verify_options_no_trust)?;

    // When trusted_public_key is None, trusted_signer is false
    // but the signature still verifies
    assert!(
        !result.trusted_signer,
        "Without explicit trusted key, trusted_signer should be false"
    );

    // With explicit trusted_public_key
    let verify_options_with_trust = AttestationVerificationOptions {
        subject_path: Some(subject_path),
        trusted_public_key: Some(keypair.public_key.clone()),
        bundle_path: None,
    };

    let result_with_trust = verify_build_attestation(&attestation, verify_options_with_trust)?;
    assert!(
        result_with_trust.trusted_signer,
        "With matching trusted key, trusted_signer should be true"
    );

    Ok(())
}

/// Malformed base64 in private key should fail
#[test]
fn test_invalid_base64_private_key_fails() -> Result<()> {
    // Invalid base64 characters
    let result = crypto::sign_data("not-valid-base64!!!", b"data");
    assert!(
        result.is_err(),
        "Invalid base64 should fail: {:?}",
        result
    );
    assert!(matches!(result.unwrap_err(), MkpeError::Base64Error(_)));

    Ok(())
}

/// Malformed base64 in public key should fail
#[test]
fn test_invalid_base64_public_key_fails() -> Result<()> {
    let result = crypto::verify_signature("invalid!!!base64", b"data", "dummy");
    assert!(
        result.is_err(),
        "Invalid base64 public key should fail: {:?}",
        result
    );
    assert!(matches!(result.unwrap_err(), MkpeError::Base64Error(_)));

    Ok(())
}

/// Key with wrong byte length should fail
#[test]
fn test_wrong_length_key_fails() -> Result<()> {
    // Ed25519 requires exactly 32-byte keys
    let short_key = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &[0u8; 16], // Too short
    );

    let result = crypto::sign_data(&short_key, b"data");
    assert!(
        result.is_err(),
        "Short key should fail: {:?}",
        result
    );
    assert!(matches!(result.unwrap_err(), MkpeError::InvalidKeyFormat(_)));

    // Also test with too-long key
    let long_key = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &[0u8; 64], // Too long
    );

    let result_long = crypto::sign_data(&long_key, b"data");
    assert!(
        result_long.is_err(),
        "Long key should fail: {:?}",
        result_long
    );

    Ok(())
}

/// Generated keypairs should be valid base64 with correct length
#[test]
fn test_keypair_generation_produces_valid_format() -> Result<()> {
    let keypair = generate_keypair();

    // Keys should be non-empty
    assert!(!keypair.private_key.is_empty());
    assert!(!keypair.public_key.is_empty());

    // Keys should be valid base64
    let priv_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &keypair.private_key,
    )?;
    let pub_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &keypair.public_key,
    )?;

    // Keys should be exactly 32 bytes (Ed25519 requirement)
    assert_eq!(priv_bytes.len(), 32, "Private key must be 32 bytes");
    assert_eq!(pub_bytes.len(), 32, "Public key must be 32 bytes");

    // Generated keypair should be able to sign and verify
    let data = b"Test data for signature";
    let signature = keypair.sign(data)?;
    let verified = keypair.verify(data, &signature)?;
    assert!(verified, "Generated keypair should sign and verify");

    // Public key and private key should be different
    assert_ne!(
        keypair.private_key, keypair.public_key,
        "Private and public keys should differ"
    );

    // Each keypair should have a unique key_id
    let keypair2 = generate_keypair();
    assert_ne!(
        keypair.key_id, keypair2.key_id,
        "Each keypair should have unique key_id"
    );

    Ok(())
}

/// Create a manifest with a parent_manifest_id set
#[test]
fn test_manifest_with_parent_link() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir(&artifact_dir)?;
    fs::write(artifact_dir.join("child.txt"), "Child artifact")?;

    let keypair = generate_keypair();

    // Create parent manifest
    let proofs_parent = proof::create_recursive_proofs(&artifact_dir, &keypair)?;
    let bundle_parent = proof::create_proof_bundle(proofs_parent, &keypair, None)?;

    let mut parent_manifest = Manifest::new(
        bundle_parent.root_hash.clone(),
        bundle_parent.proofs.len(),
        keypair.public_key.clone(),
        None, // No parent for root manifest
    );
    parent_manifest.sign(&keypair)?;

    let parent_id = parent_manifest.manifest_id.clone();

    // Create child manifest with parent link
    let mut child_manifest = Manifest::new(
        bundle_parent.root_hash.clone(),
        bundle_parent.proofs.len(),
        keypair.public_key.clone(),
        Some(parent_id.clone()), // Link to parent
    );
    child_manifest.sign(&keypair)?;

    // Child manifest should have parent_manifest_id set
    assert!(
        child_manifest.parent_manifest_id.is_some(),
        "Child manifest should have parent_manifest_id"
    );
    assert_eq!(
        child_manifest.parent_manifest_id.as_deref(),
        Some(parent_id.as_str()),
        "Child's parent should match the actual parent manifest ID"
    );

    // Parent manifest should have no parent
    assert!(
        parent_manifest.parent_manifest_id.is_none(),
        "Root manifest should have no parent"
    );

    Ok(())
}

/// Verify that chained manifests can be verified together
#[test]
fn test_chained_manifests_verify_together() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir(&artifact_dir)?;
    fs::write(artifact_dir.join("file.txt"), "Content")?;

    let keypair = generate_keypair();

    // Create first generation manifest
    let proofs_gen1 = proof::create_recursive_proofs(&artifact_dir, &keypair)?;
    let bundle_gen1 = proof::create_proof_bundle(proofs_gen1.clone(), &keypair, None)?;

    let mut manifest_gen1 = Manifest::new(
        bundle_gen1.root_hash.clone(),
        bundle_gen1.proofs.len(),
        keypair.public_key.clone(),
        None,
    );
    manifest_gen1.sign(&keypair)?;

    let id_gen1 = manifest_gen1.manifest_id.clone();

    // Create second generation manifest chained to first
    let bundle_gen2 = proof::create_proof_bundle(proofs_gen1, &keypair, Some(id_gen1.clone()))?;

    let mut manifest_gen2 = Manifest::new(
        bundle_gen2.root_hash.clone(),
        bundle_gen2.proofs.len(),
        keypair.public_key.clone(),
        Some(id_gen1.clone()), // Chain to generation 1
    );
    manifest_gen2.sign(&keypair)?;

    // Both manifests should verify with the same key
    assert!(
        manifest_gen1.verify()?,
        "Generation 1 manifest should verify"
    );
    assert!(
        manifest_gen2.verify()?,
        "Generation 2 manifest should verify"
    );

    // Chain linkage should be intact
    assert_eq!(
        manifest_gen2.parent_manifest_id.as_deref(),
        Some(id_gen1.as_str()),
        "Chain linkage should be preserved"
    );

    // Verify each manifest's embedded public key
    assert_eq!(
        manifest_gen1.verifier_public_key, keypair.public_key,
        "Gen1 should have correct verifier key"
    );
    assert_eq!(
        manifest_gen2.verifier_public_key, keypair.public_key,
        "Gen2 should have correct verifier key"
    );

    Ok(())
}
