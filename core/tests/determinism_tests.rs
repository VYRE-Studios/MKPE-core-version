//! Determinism tests for MKPE core library
//!
//! ## Documented Non-Determinism
//!
//! Some tests are marked `#[ignore]` because they document known non-determinism:
//! - Merkle tree ordering: input order affects output
//! - Signature non-determinism: JSON timestamps vary per invocation
//! - UUID generation: manifest_id uses Uuid::new_v4()

use morse_kirby_core::*;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// Documented non-deterministic behaviors (marked #[ignore])
// ============================================================================



#[test]
fn test_merkle_root_deterministic_order_agnostic() {
    let hashes: Vec<String> = (0..10)
        .map(|i| format!("{:064x}", (i as u64).wrapping_mul(0x123456789ABCDEFi64 as u64)))
        .collect();
    let mut sorted_hashes = hashes.clone();
    sorted_hashes.sort();
    let reversed_hashes: Vec<String> = sorted_hashes.iter().rev().cloned().collect();

    let root_sorted = build_merkle_root(&sorted_hashes);
    let root_reversed = build_merkle_root(&reversed_hashes);

    assert_eq!(root_sorted, root_reversed);
}



#[test]
fn test_manifest_signature_deterministic() {
    let keypair = generate_keypair();
    let mut manifest = Manifest::new("test_hash".to_string(), 1, keypair.public_key.clone(), None);
    manifest.sign(&keypair).unwrap();
    let sig1 = manifest.signature.clone();

    let mut manifest2 = Manifest::new("test_hash".to_string(), 1, keypair.public_key.clone(), None);
    manifest2.sign(&keypair).unwrap();
    let sig2 = manifest2.signature;

    assert_eq!(sig1, sig2);
}



#[test]
fn test_identical_bundle_produces_identical_manifest_id() {
    let temp_dir = TempDir::new().unwrap();
    let artifact = temp_dir.path().join("artifact");
    std::fs::create_dir_all(&artifact).unwrap();
    std::fs::write(artifact.join("file.txt"), b"content").unwrap();

    let keypair = generate_keypair();
    let archive1 = create_mkpe_bundle(&artifact, &keypair, &temp_dir.path().join("b1.mkpe")).unwrap();
    let archive2 = create_mkpe_bundle(&artifact, &keypair, &temp_dir.path().join("b2.mkpe")).unwrap();

    assert_eq!(archive1.manifest.manifest_id, archive2.manifest.manifest_id);
}



#[test]
fn test_two_bundles_same_content_verify_identically() {
    let temp_dir = TempDir::new().unwrap();
    let artifact = temp_dir.path().join("data");
    std::fs::create_dir_all(&artifact).unwrap();
    std::fs::write(artifact.join("test.txt"), b"identical content").unwrap();

    let keypair = generate_keypair();
    let _bundle1 = create_mkpe_bundle(&artifact, &keypair, &temp_dir.path().join("a1.mkpe")).unwrap();
    let _bundle2 = create_mkpe_bundle(&artifact, &keypair, &temp_dir.path().join("a2.mkpe")).unwrap();

    let loaded1 = MkpeArchive::load(&temp_dir.path().join("a1.mkpe")).unwrap();
    let loaded2 = MkpeArchive::load(&temp_dir.path().join("a2.mkpe")).unwrap();

    assert_eq!(loaded1.manifest.manifest_id, loaded2.manifest.manifest_id);
}

// ============================================================================
// Passing tests (deterministic behaviors)
// ============================================================================


fn test_directory_hash_is_deterministic() {
    let temp_dir = TempDir::new().unwrap();
    let artifact_dir = temp_dir.path().join("test");
    fs::create_dir_all(&artifact_dir).unwrap();
    fs::write(artifact_dir.join("a.txt"), b"A").unwrap();
    fs::write(artifact_dir.join("b.txt"), b"B").unwrap();

    let hash1 = hash_subject(&artifact_dir).unwrap();
    let hash2 = hash_subject(&artifact_dir).unwrap();
    assert_eq!(hash1, hash2);
}


fn test_attestation_id_unique_per_invocation() {
    let temp_dir = TempDir::new().unwrap();
    let subject = temp_dir.path().join("artifact.txt");
    fs::write(&subject, b"content").unwrap();

    let keypair = generate_keypair();
    let att1 = create_build_attestation(&subject, &keypair, AttestationOptions::default()).unwrap();
    let att2 = create_build_attestation(&subject, &keypair, AttestationOptions::default()).unwrap();
    assert_ne!(att1.attestation_id, att2.attestation_id);
}


fn test_proof_bundle_deterministic_root() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("a.txt"), b"A").unwrap();
    fs::write(temp_dir.path().join("b.txt"), b"B").unwrap();

    let keypair = generate_keypair();
    let proofs = create_recursive_proofs(temp_dir.path(), &keypair).unwrap();
    let bundle1 = create_proof_bundle(proofs.clone(), &keypair, None).unwrap();
    let bundle2 = create_proof_bundle(proofs, &keypair, None).unwrap();
    assert_eq!(bundle1.root_hash, bundle2.root_hash);
}


fn test_proof_items_sorted_regardless_of_creation_order() {
    let temp_dir = TempDir::new().unwrap();
    let artifact_dir = temp_dir.path().join("files");
    fs::create_dir_all(&artifact_dir).unwrap();
    let files = ["z_file.txt", "a_file.txt", "m_file.txt"];
    for name in files.iter() {
        fs::write(artifact_dir.join(name), b"content").unwrap();
    }

    let keypair = generate_keypair();
    let proofs = create_recursive_proofs(&artifact_dir, &keypair).unwrap();
    let proof_names: Vec<String> = proofs.iter()
        .map(|p| p.path.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    let mut sorted_names = proof_names.clone();
    sorted_names.sort();
    assert_eq!(proof_names, sorted_names);
}


fn test_single_file_directory_determinism() {
    let temp_dir = TempDir::new().unwrap();
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_dir).unwrap();
    fs::write(artifact_dir.join("file.txt"), b"content").unwrap();

    let hash1 = hash_subject(&artifact_dir).unwrap();
    let hash2 = hash_subject(&artifact_dir).unwrap();
    assert_eq!(hash1, hash2);
}


fn test_special_characters_in_filenames_determinism() {
    let temp_dir = TempDir::new().unwrap();
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_dir).unwrap();
    let special_files = ["file with spaces.txt", "file-with-dashes.txt", "file_with_underscores.txt"];
    for name in special_files.iter() {
        fs::write(artifact_dir.join(name), b"content").unwrap();
    }

    let keypair = generate_keypair();
    let proofs = create_recursive_proofs(&artifact_dir, &keypair).unwrap();
    assert_eq!(proofs.len(), special_files.len());

    let hash1 = hash_subject(&artifact_dir).unwrap();
    let hash2 = hash_subject(&artifact_dir).unwrap();
    assert_eq!(hash1, hash2);
}


fn test_empty_directory_handling() {
    let temp_dir = TempDir::new().unwrap();
    let empty_dir = temp_dir.path().join("empty");
    fs::create_dir_all(&empty_dir).unwrap();

    let hash1 = hash_subject(&empty_dir).unwrap();
    let hash2 = hash_subject(&empty_dir).unwrap();
    assert_eq!(hash1, hash2);
    assert_eq!(hash1.len(), 64);
}


fn test_large_file_count_determinism() {
    let temp_dir = TempDir::new().unwrap();
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_dir).unwrap();

    for i in 0..50 {
        fs::write(artifact_dir.join(format!("file{:03}.txt", i)), b"content").unwrap();
    }

    let hash1 = hash_subject(&artifact_dir).unwrap();
    let hash2 = hash_subject(&artifact_dir).unwrap();
    assert_eq!(hash1, hash2);
}