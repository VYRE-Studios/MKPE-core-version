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
    std::fs::write(&private_key, keypair.private_key).unwrap();
    std::fs::write(&public_key, keypair.public_key).unwrap();
    (private_key, public_key)
}

#[test]
fn test_attest_generate_and_verify_json() {
    let temp_dir = TempDir::new().unwrap();
    let subject = temp_dir.path().join("artifact.txt");
    let attestation = temp_dir.path().join("build_attestation.json");
    std::fs::write(&subject, b"release bytes").unwrap();
    let (private_key, public_key) = write_keypair(&temp_dir);

    let generate = mkpe()
        .args([
            "--format",
            "json",
            "attest",
            "generate",
            subject.to_str().unwrap(),
            "--key",
            private_key.to_str().unwrap(),
            "--output",
            attestation.to_str().unwrap(),
            "--attested-by",
            "ci",
            "--command",
            "cargo build --release",
        ])
        .output()
        .unwrap();

    assert!(generate.status.success());
    let generated: serde_json::Value = serde_json::from_slice(&generate.stdout).unwrap();
    assert_eq!(generated["status"], "created");
    assert!(attestation.exists());

    let verify = mkpe()
        .args([
            "--format",
            "json",
            "attest",
            "verify",
            attestation.to_str().unwrap(),
            "--subject",
            subject.to_str().unwrap(),
            "--public-key",
            public_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(verify.status.success());
    let verified: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verified["status"], "verified");
    assert_eq!(verified["trusted_signer"], true);
}

#[test]
fn test_attest_verify_json_reports_tamper_exit_2() {
    let temp_dir = TempDir::new().unwrap();
    let subject = temp_dir.path().join("artifact.txt");
    let attestation = temp_dir.path().join("build_attestation.json");
    std::fs::write(&subject, b"release bytes").unwrap();
    let (private_key, public_key) = write_keypair(&temp_dir);

    let generate = mkpe()
        .args([
            "attest",
            "generate",
            subject.to_str().unwrap(),
            "--key",
            private_key.to_str().unwrap(),
            "--output",
            attestation.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(generate.status.success());

    std::fs::write(&subject, b"tampered bytes").unwrap();

    let verify = mkpe()
        .args([
            "--format",
            "json",
            "attest",
            "verify",
            attestation.to_str().unwrap(),
            "--subject",
            subject.to_str().unwrap(),
            "--public-key",
            public_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(verify.status.code(), Some(2));
    let failed: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(failed["status"], "failed");
    assert!(failed["reason"]
        .as_str()
        .unwrap()
        .contains("Subject hash mismatch"));
}

#[test]
fn test_attest_verify_json_reports_malformed_input_exit_3() {
    let temp_dir = TempDir::new().unwrap();
    let attestation = temp_dir.path().join("build_attestation.json");
    std::fs::write(&attestation, b"{not valid json").unwrap();

    let verify = mkpe()
        .args([
            "--format",
            "json",
            "attest",
            "verify",
            attestation.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(verify.status.code(), Some(3));
    let failed: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(failed["status"], "failed");
    assert!(failed["reason"].as_str().unwrap().contains("JSON error"));
}

#[test]
fn test_attest_verify_json_requires_public_key_exit_3() {
    let temp_dir = TempDir::new().unwrap();
    let subject = temp_dir.path().join("artifact.txt");
    let attestation = temp_dir.path().join("build_attestation.json");
    std::fs::write(&subject, b"release bytes").unwrap();
    let (private_key, _) = write_keypair(&temp_dir);

    let generate = mkpe()
        .args([
            "attest",
            "generate",
            subject.to_str().unwrap(),
            "--key",
            private_key.to_str().unwrap(),
            "--output",
            attestation.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(generate.status.success());

    let verify = mkpe()
        .args([
            "--format",
            "json",
            "attest",
            "verify",
            attestation.to_str().unwrap(),
            "--subject",
            subject.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(verify.status.code(), Some(3));
    let failed: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(failed["status"], "failed");
    assert!(failed["reason"].as_str().unwrap().contains("public key"));
}

#[test]
fn test_attest_verify_json_rejects_wrong_public_key_exit_2() {
    let temp_dir = TempDir::new().unwrap();
    let subject = temp_dir.path().join("artifact.txt");
    let attestation = temp_dir.path().join("build_attestation.json");
    std::fs::write(&subject, b"release bytes").unwrap();
    let (private_key, _) = write_keypair(&temp_dir);
    let wrong_public_key = temp_dir.path().join("wrong_public.key");
    std::fs::write(&wrong_public_key, generate_keypair().public_key).unwrap();

    let generate = mkpe()
        .args([
            "attest",
            "generate",
            subject.to_str().unwrap(),
            "--key",
            private_key.to_str().unwrap(),
            "--output",
            attestation.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(generate.status.success());

    let verify = mkpe()
        .args([
            "--format",
            "json",
            "attest",
            "verify",
            attestation.to_str().unwrap(),
            "--subject",
            subject.to_str().unwrap(),
            "--public-key",
            wrong_public_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(verify.status.code(), Some(2));
    let failed: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(failed["status"], "failed");
    assert!(failed["reason"]
        .as_str()
        .unwrap()
        .contains("trusted public key"));
}

#[test]
fn test_attest_verify_json_rejects_unknown_unsigned_field_exit_3() {
    let temp_dir = TempDir::new().unwrap();
    let subject = temp_dir.path().join("artifact.txt");
    let attestation = temp_dir.path().join("build_attestation.json");
    std::fs::write(&subject, b"release bytes").unwrap();
    let (private_key, public_key) = write_keypair(&temp_dir);

    let generate = mkpe()
        .args([
            "attest",
            "generate",
            subject.to_str().unwrap(),
            "--key",
            private_key.to_str().unwrap(),
            "--output",
            attestation.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(generate.status.success());

    let mut document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&attestation).unwrap()).unwrap();
    document["trusted_signer"] = serde_json::json!(true);
    std::fs::write(
        &attestation,
        serde_json::to_string_pretty(&document).unwrap(),
    )
    .unwrap();

    let verify = mkpe()
        .args([
            "--format",
            "json",
            "attest",
            "verify",
            attestation.to_str().unwrap(),
            "--subject",
            subject.to_str().unwrap(),
            "--public-key",
            public_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(verify.status.code(), Some(3));
    let failed: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(failed["status"], "failed");
    assert!(failed["reason"].as_str().unwrap().contains("unknown field"));
}
