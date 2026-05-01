//! Integration tests for MKPE core library

use morse_kirby_core::proof::create_recursive_proofs;
use morse_kirby_core::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_complete_workflow() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir(&artifact_dir)?;

    // 1. Generate keypair
    let keypair = generate_keypair();
    assert!(!keypair.private_key.is_empty());
    assert!(!keypair.public_key.is_empty());

    // 2. Create test files
    for i in 0..5 {
        fs::write(
            artifact_dir.join(format!("file{}.txt", i)),
            format!("Content {}", i),
        )?;
    }

    // 3. Create proofs
    let proofs = create_recursive_proofs(&artifact_dir, &keypair)?;
    assert_eq!(proofs.len(), 5);

    // 4. Create bundle
    let bundle = morse_kirby_core::proof::create_proof_bundle(proofs, &keypair, None)?;
    assert_eq!(bundle.proofs.len(), 5);

    // 5. Create and sign manifest
    let mut manifest = Manifest::new(
        bundle.root_hash.clone(),
        bundle.proofs.len(),
        keypair.public_key.clone(),
        None,
    );
    manifest.sign(&keypair)?;

    // 6. Verify manifest
    assert!(manifest.verify()?);

    // 7. Create archive
    let archive_path = temp_dir.path().join("test.mkpe");
    create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;

    // 8. Load and verify archive
    let loaded = MkpeArchive::load(&archive_path)?;
    assert!(loaded.verify().is_ok());

    Ok(())
}

#[test]
fn test_cdna_workflow() -> Result<()> {
    let keypair = generate_keypair();

    // Create C-DNA schema
    let mut schema = CdnaSchema::new(
        "test.program.v1".to_string(),
        "Test program for integration".to_string(),
    );

    // Add nodes
    let node = CdnaNode {
        id: "n1".to_string(),
        node_type: "test_node".to_string(),
        description: Some("Test node".to_string()),
        params: None,
        ports: None,
        implementation: None,
    };
    schema.nodes.push(node);

    // Create proof
    let proof = schema.create_proof(&keypair)?;
    assert!(proof.verify()?);

    Ok(())
}
