use morse_kirby_core::generate_keypair;
use std::process::Command;
use tempfile::TempDir;

fn mkpe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mkpe"))
}

fn write_keypair(temp_dir: &TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    let keypair = generate_keypair();
    let key_dir = temp_dir.path().join("keys");
    std::fs::create_dir(&key_dir).unwrap();
    let private_key = key_dir.join("mkpe_private.key");
    let public_key = key_dir.join("mkpe_public.key");
    std::fs::write(&private_key, &keypair.private_key).unwrap();
    std::fs::write(&public_key, &keypair.public_key).unwrap();
    (private_key, public_key)
}

#[test]
fn test_dna_embed_and_extract_json() {
    let temp_dir = TempDir::new().unwrap();
    let artifact = temp_dir.path().join("artifact.bin");
    let attestation = temp_dir.path().join("attestation.json");
    let tagged = temp_dir.path().join("tagged.bin");

    // Create a 4 KiB artifact filled with non-zero noise
    let mut bytes = vec![0u8; 4096];
    for i in 0..bytes.len() {
        bytes[i] = ((i * 7 + 13) % 256) as u8;
    }
    std::fs::write(&artifact, &bytes).unwrap();

    // Create a dummy attestation JSON
    std::fs::write(
        &attestation,
        serde_json::json!({
            "schema_version": "1.0",
            "attestation_id": "test-123",
            "subject_path": artifact.to_str().unwrap(),
            "subject_sha256": "deadbeef",
        })
        .to_string(),
    )
    .unwrap();

    let (private_key, _public_key) = write_keypair(&temp_dir);

    // Embed DNA tag
    let embed = mkpe()
        .args([
            "--format",
            "json",
            "dna",
            "embed",
            artifact.to_str().unwrap(),
            "--attestation",
            attestation.to_str().unwrap(),
            "--key",
            private_key.to_str().unwrap(),
            "--output",
            tagged.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        embed.status.success(),
        "embed failed: stderr = {}",
        String::from_utf8_lossy(&embed.stderr)
    );
    let embedded: serde_json::Value = serde_json::from_slice(&embed.stdout).unwrap();
    assert_eq!(embedded["status"], "embedded");
    assert!(tagged.exists());

    // Extract and verify DNA tag
    let extract = mkpe()
        .args([
            "--format",
            "json",
            "dna",
            "extract",
            tagged.to_str().unwrap(),
            "--key",
            private_key.to_str().unwrap(),
            "--attestation",
            attestation.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        extract.status.success(),
        "extract failed: stderr = {}",
        String::from_utf8_lossy(&extract.stderr)
    );
    let extracted: serde_json::Value = serde_json::from_slice(&extract.stdout).unwrap();
    assert_eq!(extracted["status"], "verified");
    assert_eq!(extracted["verified"], true);
}

#[test]
fn test_dna_extract_wrong_attestation_fails() {
    let temp_dir = TempDir::new().unwrap();
    let artifact = temp_dir.path().join("artifact.bin");
    let attestation = temp_dir.path().join("attestation.json");
    let wrong_attestation = temp_dir.path().join("wrong.json");
    let tagged = temp_dir.path().join("tagged.bin");

    let mut bytes = vec![0u8; 4096];
    for i in 0..bytes.len() {
        bytes[i] = ((i * 7 + 13) % 256) as u8;
    }
    std::fs::write(&artifact, &bytes).unwrap();

    std::fs::write(
        &attestation,
        serde_json::json!({ "id": "real" }).to_string(),
    )
    .unwrap();
    std::fs::write(
        &wrong_attestation,
        serde_json::json!({ "id": "fake" }).to_string(),
    )
    .unwrap();

    let (private_key, _public_key) = write_keypair(&temp_dir);

    // Embed with real attestation
    let embed = mkpe()
        .args([
            "dna",
            "embed",
            artifact.to_str().unwrap(),
            "--attestation",
            attestation.to_str().unwrap(),
            "--key",
            private_key.to_str().unwrap(),
            "--output",
            tagged.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(embed.status.success());

    // Extract with wrong attestation should fail
    let extract = mkpe()
        .args([
            "dna",
            "extract",
            tagged.to_str().unwrap(),
            "--key",
            private_key.to_str().unwrap(),
            "--attestation",
            wrong_attestation.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!extract.status.success());
    let stderr = String::from_utf8_lossy(&extract.stderr);
    assert!(stderr.contains("does not match attestation hash"));
}

#[test]
fn test_dna_extract_wrong_key_fails() {
    let temp_dir = TempDir::new().unwrap();
    let artifact = temp_dir.path().join("artifact.bin");
    let attestation = temp_dir.path().join("attestation.json");
    let tagged = temp_dir.path().join("tagged.bin");

    let mut bytes = vec![0u8; 4096];
    for i in 0..bytes.len() {
        bytes[i] = ((i * 7 + 13) % 256) as u8;
    }
    std::fs::write(&artifact, &bytes).unwrap();
    std::fs::write(&attestation,
        serde_json::json!({ "id": "real" }).to_string(),
    ).unwrap();

    let (private_key, _public_key) = write_keypair(&temp_dir);

    // Generate a second, different keypair for the wrong key
    let wrong_keypair = generate_keypair();
    let wrong_key = temp_dir.path().join("wrong_private.key");
    let wrong_pub = temp_dir.path().join("wrong_public.key");
    std::fs::write(&wrong_key, &wrong_keypair.private_key).unwrap();
    std::fs::write(&wrong_pub, &wrong_keypair.public_key).unwrap();

    // Embed with correct key
    let embed = mkpe()
        .args([
            "dna",
            "embed",
            artifact.to_str().unwrap(),
            "--attestation",
            attestation.to_str().unwrap(),
            "--key",
            private_key.to_str().unwrap(),
            "--output",
            tagged.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(embed.status.success());

    // Extract with wrong key should fail (CRC mismatch or missing tag)
    let extract = mkpe()
        .args([
            "dna",
            "extract",
            tagged.to_str().unwrap(),
            "--key",
            wrong_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!extract.status.success());
}
