//! Integration tests for MKPE v1.1+ upgraded features:
//! - Replay protection (nonce)
//! - Manifest chaining and depth
//! - Key rotation and revocation
//! - Policy engine
//! - SLSA predicate generation
//! - DSSE envelope
//! - Multi-signature threshold
//! - Merkle audit log

use morse_kirby_core::*;
use std::collections::BTreeSet;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// Manifest Nonce & Chain Depth
// ============================================================================

#[test]
fn test_manifest_nonce_verification_passes_when_fresh() -> Result<()> {
    let keypair = generate_keypair();
    let mut manifest = Manifest::new("hash123".to_string(), 3, keypair.public_key.clone(), None);
    manifest.nonce = Some(100);
    manifest.sign(&keypair)?;

    assert!(manifest.verify_nonce(50));
    assert!(manifest.verify_nonce(100));
    assert!(!manifest.verify_nonce(101));
    Ok(())
}

#[test]
fn test_manifest_nonce_verification_fails_when_missing() -> Result<()> {
    let keypair = generate_keypair();
    let mut manifest = Manifest::new("hash123".to_string(), 3, keypair.public_key.clone(), None);
    manifest.nonce = None;
    manifest.sign(&keypair)?;

    assert!(!manifest.verify_nonce(1));
    Ok(())
}

#[test]
fn test_manifest_is_genesis_when_no_parent() -> Result<()> {
    let manifest = Manifest::new("hash123".to_string(), 3, "pk".to_string(), None);
    assert!(manifest.is_genesis());
    Ok(())
}

#[test]
fn test_manifest_is_not_genesis_with_parent() -> Result<()> {
    let manifest = Manifest::new(
        "hash123".to_string(),
        3,
        "pk".to_string(),
        Some("parent-id".to_string()),
    );
    assert!(!manifest.is_genesis());
    Ok(())
}

#[test]
fn test_manifest_chain_depth_from_metadata() -> Result<()> {
    let mut manifest = Manifest::new("hash123".to_string(), 3, "pk".to_string(), Some("parent".to_string()));
    assert_eq!(manifest.chain_depth(), 2);

    manifest.add_metadata("chain_depth".to_string(), serde_json::json!(5u64));
    assert_eq!(manifest.chain_depth(), 5);
    Ok(())
}

#[test]
fn test_manifest_signature_includes_nonce() -> Result<()> {
    let keypair = generate_keypair();
    let mut manifest = Manifest::new("hash123".to_string(), 3, keypair.public_key.clone(), None);
    manifest.nonce = Some(42);
    manifest.sign(&keypair)?;
    assert!(manifest.verify()?);
    Ok(())
}

// ============================================================================
// Key Rotation & Revocation
// ============================================================================

#[test]
fn test_key_metadata_creation() {
    let km = KeyMetadata {
        key_id: "key-1".to_string(),
        version: 1,
        created_at: chrono::Utc::now(),
        expires_at: None,
        predecessor_key_id: None,
    };
    assert_eq!(km.version, 1);
}

#[test]
fn test_revocation_list_contains_revoked_key() {
    let rl = RevocationList {
        revoked_keys: vec!["revoked-key".to_string()],
        timestamp: chrono::Utc::now(),
    };
	assert!(rl.revoked_keys.iter().any(|k| k == "revoked-key"));
}

#[test]
fn test_manifest_verify_key_rotation_passes_for_trusted_key() -> Result<()> {
    let keypair = generate_keypair();
    let mut manifest = Manifest::new("hash123".to_string(), 3, keypair.public_key.clone(), None);
    manifest.sign(&keypair)?;

    let mut trusted = BTreeSet::new();
    trusted.insert(keypair.public_key.clone());

    assert!(manifest.verify_key_rotation(&trusted, None)?);
    Ok(())
}

#[test]
fn test_manifest_verify_key_rotation_fails_for_untrusted_key() -> Result<()> {
    let keypair = generate_keypair();
    let other = generate_keypair();
    let mut manifest = Manifest::new("hash123".to_string(), 3, keypair.public_key.clone(), None);
    manifest.sign(&keypair)?;

    let mut trusted = BTreeSet::new();
    trusted.insert(other.public_key.clone());

    assert!(manifest.verify_key_rotation(&trusted, None).is_err());
    Ok(())
}

#[test]
fn test_manifest_verify_key_rotation_fails_for_revoked_key() -> Result<()> {
    let keypair = generate_keypair();
    let mut manifest = Manifest::new("hash123".to_string(), 3, keypair.public_key.clone(), None);
    manifest.sign(&keypair)?;

    let mut trusted = BTreeSet::new();
    trusted.insert(keypair.public_key.clone());

    let rl = RevocationList {
        revoked_keys: vec![keypair.public_key.clone()],
        timestamp: chrono::Utc::now(),
    };

    assert!(!manifest.verify_key_rotation(&trusted, Some(&rl))?);
    Ok(())
}

// ============================================================================
// Policy Engine
// ============================================================================

#[test]
fn test_policy_engine_enforces_key_version() -> Result<()> {
    let mut manifest = Manifest::new("hash123".to_string(), 3, "pk".to_string(), None);
    manifest.engine_version = "2.0.0".to_string();

    let engine = PolicyEngine {
        policies: vec![Policy {
            name: "min_version".to_string(),
            conditions: vec![PolicyCondition::KeyVersion { min: 2 }],
            require_all: true,
        }],
    };
    assert!(engine.verify(&manifest)?);

    manifest.engine_version = "1.0.0".to_string();
    assert!(!engine.verify(&manifest)?);
    Ok(())
}

#[test]
fn test_policy_engine_enforces_bundle_hash() -> Result<()> {
    let manifest = Manifest::new("expected_hash".to_string(), 3, "pk".to_string(), None);

    let engine = PolicyEngine {
        policies: vec![Policy {
            name: "hash_match".to_string(),
            conditions: vec![PolicyCondition::BundleHash {
                expected: "expected_hash".to_string(),
            }],
            require_all: true,
        }],
    };
    assert!(engine.verify(&manifest)?);
    Ok(())
}

#[test]
fn test_policy_engine_json_load_and_verify() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("policy.json");

    let engine = PolicyEngine {
        policies: vec![Policy {
            name: "test".to_string(),
            conditions: vec![PolicyCondition::ChainDepth { min: 1 }],
            require_all: true,
        }],
    };
    fs::write(&path, serde_json::to_string(&engine)?)?;

    let loaded = PolicyEngine::load_from_json(&path)?;
    let manifest = Manifest::new("hash".to_string(), 3, "pk".to_string(), None);
    assert!(loaded.verify(&manifest)?);
    Ok(())
}

// ============================================================================
// SLSA Predicate Generation
// ============================================================================

#[test]
fn test_build_attestation_slsa_predicate_structure() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let subject = temp_dir.path().join("artifact.bin");
    fs::write(&subject, b"binary content")?;

    let keypair = generate_keypair();
    let attestation = create_build_attestation(&subject, &keypair, AttestationOptions::default())?;
    let predicate = attestation.to_slsa_predicate();

    assert_eq!(
        predicate.get("_type").and_then(|v| v.as_str()),
        Some("https://in-toto.io/Statement/v1")
    );
    assert_eq!(
        predicate.get("predicateType").and_then(|v| v.as_str()),
        Some("https://slsa.dev/provenance/v1")
    );
    assert!(
        predicate.get("subject").and_then(|v| v.as_array()).is_some(),
        "subject array must exist"
    );
    Ok(())
}

#[test]
fn test_build_attestation_slsa_predicate_with_build_info() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let subject = temp_dir.path().join("artifact.bin");
    fs::write(&subject, b"binary content")?;

    let keypair = generate_keypair();
    let mut attestation = create_build_attestation(&subject, &keypair, AttestationOptions::default())?;
    attestation.build_info = Some(BuildInfo {
        builder_id: "builder-1".to_string(),
        build_type: "cargo".to_string(),
        build_definition: "default".to_string(),
        source_repository: Some("https://github.com/example/repo".to_string()),
        source_commit: Some("abc123".to_string()),
        dependencies: vec![Dependency {
            name: "serde".to_string(),
            version: "1.0".to_string(),
            source: "crates.io".to_string(),
            integrity: "sha256:deadbeef".to_string(),
        }],
        environment: std::collections::HashMap::new(),
    });

    let predicate = attestation.to_slsa_predicate();
    let prov = predicate.get("predicate").unwrap();
    let run_details = prov.get("runDetails").unwrap();
    assert_eq!(
        run_details.get("builder").and_then(|b| b.get("id")).and_then(|v| v.as_str()),
        Some("builder-1")
    );

    let build_def = prov.get("buildDefinition").unwrap();
    let deps = build_def.get("resolvedDependencies").and_then(|v| v.as_array()).unwrap();
    assert_eq!(deps.len(), 1);
    Ok(())
}

// ============================================================================
// DSSE Envelope
// ============================================================================

#[test]
fn test_dsse_envelope_manifest_roundtrip() -> Result<()> {
    let keypair = generate_keypair();
    let mut manifest = Manifest::new("hash123".to_string(), 3, keypair.public_key.clone(), None);
    manifest.sign(&keypair)?;

    let envelope = DSSEEnvelope::from_manifest(&manifest, &keypair)?;
    assert!(envelope.verify(&keypair.public_key)?);

    let json = envelope.to_json()?;
    let restored = DSSEEnvelope::from_json(&json)?;
    assert!(restored.verify(&keypair.public_key)?);
    Ok(())
}

#[test]
fn test_dsse_envelope_rejects_wrong_key() -> Result<()> {
    let keypair = generate_keypair();
    let wrong = generate_keypair();
    let manifest = Manifest::new("hash123".to_string(), 3, keypair.public_key.clone(), None);

    let envelope = DSSEEnvelope::from_manifest(&manifest, &keypair)?;
    assert!(!envelope.verify(&wrong.public_key)?);
    Ok(())
}

// ============================================================================
// Multi-Signature Threshold
// ============================================================================

#[test]
fn test_multisig_threshold_met_with_two_keys() -> Result<()> {
    let manifest = Manifest::new("hash123".to_string(), 3, "pk".to_string(), None);
    let mut msm = MultiSignatureManifest::new(manifest, 2);

    let kp1 = generate_keypair();
    let kp2 = generate_keypair();
    msm.add_signature(&kp1)?;
    msm.add_signature(&kp2)?;

    let trusted = vec![kp1.public_key.clone(), kp2.public_key.clone()];
    assert!(msm.verify(&trusted)?);
    Ok(())
}

#[test]
fn test_multisig_threshold_not_met_with_one_key() -> Result<()> {
    let manifest = Manifest::new("hash123".to_string(), 3, "pk".to_string(), None);
    let mut msm = MultiSignatureManifest::new(manifest, 2);

    let kp1 = generate_keypair();
    msm.add_signature(&kp1)?;

    let trusted = vec![kp1.public_key.clone()];
    assert!(!msm.verify(&trusted)?);
    Ok(())
}

#[test]
fn test_multisig_same_key_cannot_count_twice() -> Result<()> {
    let manifest = Manifest::new("hash123".to_string(), 3, "pk".to_string(), None);
    let mut msm = MultiSignatureManifest::new(manifest, 2);

    let kp1 = generate_keypair();
    msm.add_signature(&kp1)?;
    msm.add_signature(&kp1)?;

    let trusted = vec![kp1.public_key.clone()];
    assert!(!msm.verify(&trusted)?);
    Ok(())
}

// ============================================================================
// Merkle Audit Log
// ============================================================================

#[test]
fn test_audit_log_chain_integrity() -> Result<()> {
    let temp_file = tempfile::NamedTempFile::new()?;
    let log = AuditLog::new(temp_file.path())?;

    let e1 = AuditEvent::new(AuditEventType::SystemStart, None, "start".to_string(), "INFO");
    log.log_chained(e1)?;

    let e2 = AuditEvent::new(AuditEventType::BundleCreated, Some("b1".to_string()), "created".to_string(), "INFO");
    log.log_chained(e2)?;

    assert!(log.verify_chain()?);
    Ok(())
}

#[test]
fn test_audit_log_chain_detects_tampering() -> Result<()> {
    let temp_file = tempfile::NamedTempFile::new()?;
    let log = AuditLog::new(temp_file.path())?;

    let e1 = AuditEvent::new(AuditEventType::SystemStart, None, "start".to_string(), "INFO");
    log.log_chained(e1)?;

    let e2 = AuditEvent::new(AuditEventType::BundleCreated, Some("b1".to_string()), "created".to_string(), "INFO");
    log.log_chained(e2)?;

	// Tamper with the file by corrupting the previous_hash in the second line
	let lines: Vec<String> = fs::read_to_string(temp_file.path())?.lines().map(|s| s.to_string()).collect();
	assert_eq!(lines.len(), 2);
	let mut tampered = lines[1].clone();
	// Replace the previous_hash value with an invalid hash to break the chain
	tampered = tampered.replace("previous_hash\":\"", "previous_hash\":\"INVALID");
	fs::write(temp_file.path(), format!("{}\n{}\n", lines[0], tampered))?;
    assert!(!log.verify_chain()?);
    Ok(())
}

#[test]
fn test_audit_log_merkle_root_computed() -> Result<()> {
    let temp_file = tempfile::NamedTempFile::new()?;
    let log = AuditLog::new(temp_file.path())?;

    let e1 = AuditEvent::new(AuditEventType::SystemStart, None, "start".to_string(), "INFO");
    log.log(&e1)?;

    let root = log.compute_merkle_root()?;
    assert!(root.is_some());
    assert_eq!(root.unwrap().len(), 64); // SHA-256 hex length
    Ok(())
}

#[test]
fn test_audit_log_merkle_root_empty_is_none() -> Result<()> {
    let temp_file = tempfile::NamedTempFile::new()?;
    let log = AuditLog::new(temp_file.path())?;

    let root = log.compute_merkle_root()?;
    assert!(root.is_none());
    Ok(())
}

// ============================================================================
// Attestation Nonce
// ============================================================================

#[test]
fn test_build_attestation_nonce_is_present() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let subject = temp_dir.path().join("file.txt");
    fs::write(&subject, b"content")?;

    let keypair = generate_keypair();
    let attestation = create_build_attestation(&subject, &keypair, AttestationOptions::default())?;

    assert!(attestation.nonce.is_some(), "Attestation must include a nonce");
    assert!(attestation.verify_nonce(1), "Nonce should be greater than 1");
    Ok(())
}

#[test]
fn test_build_attestation_nonce_is_signed() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let subject = temp_dir.path().join("file.txt");
    fs::write(&subject, b"content")?;

    let keypair = generate_keypair();
    let attestation = create_build_attestation(&subject, &keypair, AttestationOptions::default())?;

    let options = AttestationVerificationOptions {
        subject_path: Some(subject.clone()),
        trusted_public_key: Some(keypair.public_key.clone()),
        bundle_path: None,
    };
    let report = verify_build_attestation(&attestation, options)?;
    assert!(report.trusted_signer);
    Ok(())
}
