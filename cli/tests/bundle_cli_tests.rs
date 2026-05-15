use morse_kirby_core::{generate_keypair, OwnershipChain, TransferManifest, TransferTerms};
use std::process::Command;
use tempfile::TempDir;

fn mkpe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mkpe"))
}

fn write_keypair(temp_dir: &TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    let keypair = generate_keypair();
    let key_dir = temp_dir.path().join("keys");
    std::fs::create_dir_all(&key_dir).unwrap();
    let private_key = key_dir.join("mkpe_private.key");
    let public_key = key_dir.join("mkpe_public.key");
    std::fs::write(&private_key, &keypair.private_key).unwrap();
    std::fs::write(&public_key, &keypair.public_key).unwrap();
    (private_key, public_key)
}

#[test]
fn test_bundle_with_ownership_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let (creator_priv, _creator_pub) = write_keypair(&temp_dir);
    let (buyer_priv, _buyer_pub) = write_keypair(&temp_dir);

    // Create artifact directory
    let artifact_dir = temp_dir.path().join("artifact");
    std::fs::create_dir(&artifact_dir).unwrap();
    std::fs::write(artifact_dir.join("asset.txt"), b"proven bytes").unwrap();

    // Build ownership chain
    let mut chain = OwnershipChain::new("asset-1".to_string(), "genesis-1".to_string());
    let creator_keypair = generate_keypair();
    let buyer_keypair = generate_keypair();
    let mut manifest = TransferManifest::new(
        "asset-1".to_string(),
        Some("genesis-1".to_string()),
        creator_keypair.key_id.clone(),
        buyer_keypair.key_id.clone(),
        None,
        42,
        TransferTerms::default(),
        vec![creator_keypair.key_id.clone(), buyer_keypair.key_id.clone()],
    );
    manifest.sign(&creator_keypair).unwrap();
    manifest.sign(&buyer_keypair).unwrap();
    let mut pubkeys = std::collections::HashMap::new();
    pubkeys.insert(creator_keypair.key_id.clone(), creator_keypair.public_key.clone());
    pubkeys.insert(buyer_keypair.key_id.clone(), buyer_keypair.public_key.clone());
    chain.append(manifest, &pubkeys).unwrap();

    // Serialize ownership chain
    let ownership_json = temp_dir.path().join("ownership.json");
    let chain_json = serde_json::to_string_pretty(&chain).unwrap();
    std::fs::write(&ownership_json, chain_json).unwrap();

    // Bundle with ownership
    let bundle_path = temp_dir.path().join("artifact.mkpe");
    let output = mkpe()
        .args([
            "bundle",
            &artifact_dir.to_string_lossy(),
            "--key",
            &creator_priv.to_string_lossy(),
            "--output",
            &bundle_path.to_string_lossy(),
            "--ownership",
            &ownership_json.to_string_lossy(),
        ])
        .output()
        .expect("mkpe bundle command failed");

    assert!(output.status.success(), "bundle command failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Ownership:"), "Expected ownership in output: {}", stdout);
    assert!(stdout.contains("embedded"), "Expected 'embedded' in output: {}", stdout);

    // Verify bundle with detailed output
    let verify_output = mkpe()
        .args([
            "verify",
            &bundle_path.to_string_lossy(),
            "--detailed",
        ])
        .output()
        .expect("mkpe verify command failed");

    assert!(verify_output.status.success(), "verify command failed: {}", String::from_utf8_lossy(&verify_output.stderr));
    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(verify_stdout.contains("Ownership:"), "Expected ownership in verify output: {}", verify_stdout);
}
