use morse_kirby_core::{
    create_build_attestation, create_mkpe_bundle, generate_keypair, verify_build_attestation,
    AttestationOptions, AttestationVerificationOptions, MkpeError,
};
use tempfile::TempDir;

#[test]
fn test_attestation_verifies_subject_and_trusted_signer() -> morse_kirby_core::Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let subject = temp_dir.path().join("release.bin");
    std::fs::write(&subject, b"release bytes")?;

    let attestation = create_build_attestation(
        &subject,
        &keypair,
        AttestationOptions {
            attested_by: "ci".to_string(),
            command: Some("cargo build --release".to_string()),
            bundle_path: None,
        },
    )?;

    let report = verify_build_attestation(
        &attestation,
        AttestationVerificationOptions {
            subject_path: Some(subject.clone()),
            trusted_public_key: Some(keypair.public_key.clone()),
            bundle_path: None,
        },
    )?;

    assert_eq!(report.subject_sha256, attestation.subject_sha256);
    assert!(report.trusted_signer);
    assert_eq!(report.bundle_root_hash, None);

    Ok(())
}

#[test]
fn test_attestation_rejects_tampered_subject() -> morse_kirby_core::Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let subject = temp_dir.path().join("release.bin");
    std::fs::write(&subject, b"release bytes")?;

    let attestation = create_build_attestation(&subject, &keypair, AttestationOptions::default())?;
    std::fs::write(&subject, b"tampered release bytes")?;

    let error = verify_build_attestation(
        &attestation,
        AttestationVerificationOptions {
            subject_path: Some(subject),
            trusted_public_key: Some(keypair.public_key.clone()),
            bundle_path: None,
        },
    )
    .unwrap_err();

    assert!(matches!(error, MkpeError::VerificationFailed(_)));

    Ok(())
}

#[test]
fn test_attestation_rejects_subject_kind_mismatch() -> morse_kirby_core::Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let empty_file = temp_dir.path().join("empty.bin");
    let empty_dir = temp_dir.path().join("empty-dir");
    std::fs::write(&empty_file, b"")?;
    std::fs::create_dir(&empty_dir)?;

    let attestation =
        create_build_attestation(&empty_file, &keypair, AttestationOptions::default())?;

    let error = verify_build_attestation(
        &attestation,
        AttestationVerificationOptions {
            subject_path: Some(empty_dir),
            trusted_public_key: Some(keypair.public_key.clone()),
            bundle_path: None,
        },
    )
    .unwrap_err();

    assert!(matches!(error, MkpeError::VerificationFailed(_)));

    Ok(())
}

#[test]
fn test_attestation_rejects_tampered_signed_field() -> morse_kirby_core::Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let subject = temp_dir.path().join("release.bin");
    std::fs::write(&subject, b"release bytes")?;

    let mut attestation =
        create_build_attestation(&subject, &keypair, AttestationOptions::default())?;
    attestation.attested_by = "forged-ci".to_string();

    let error = verify_build_attestation(
        &attestation,
        AttestationVerificationOptions {
            subject_path: Some(subject),
            trusted_public_key: Some(keypair.public_key.clone()),
            bundle_path: None,
        },
    )
    .unwrap_err();

    assert!(matches!(error, MkpeError::VerificationFailed(_)));

    Ok(())
}

#[test]
fn test_directory_attestation_includes_mkpe_payload_files() -> morse_kirby_core::Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let subject = temp_dir.path().join("artifact");
    std::fs::create_dir(&subject)?;
    std::fs::write(subject.join(".mkpe"), b"payload bytes")?;

    let attestation = create_build_attestation(&subject, &keypair, AttestationOptions::default())?;
    std::fs::write(subject.join(".mkpe"), b"tampered payload bytes")?;

    let error = verify_build_attestation(
        &attestation,
        AttestationVerificationOptions {
            subject_path: Some(subject),
            trusted_public_key: Some(keypair.public_key.clone()),
            bundle_path: None,
        },
    )
    .unwrap_err();

    assert!(matches!(error, MkpeError::VerificationFailed(_)));

    Ok(())
}

#[test]
fn test_attestation_rejects_wrong_trusted_key() -> morse_kirby_core::Result<()> {
    let temp_dir = TempDir::new()?;
    let signer = generate_keypair();
    let stranger = generate_keypair();
    let subject = temp_dir.path().join("release.bin");
    std::fs::write(&subject, b"release bytes")?;

    let attestation = create_build_attestation(&subject, &signer, AttestationOptions::default())?;

    let error = verify_build_attestation(
        &attestation,
        AttestationVerificationOptions {
            subject_path: Some(subject),
            trusted_public_key: Some(stranger.public_key),
            bundle_path: None,
        },
    )
    .unwrap_err();

    assert!(matches!(error, MkpeError::VerificationFailed(_)));

    Ok(())
}

#[test]
fn test_attestation_rejects_unrelated_bundle_linkage() -> morse_kirby_core::Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let subject = temp_dir.path().join("release.bin");
    let unrelated = temp_dir.path().join("unrelated.bin");
    std::fs::write(&subject, b"release bytes")?;
    std::fs::write(&unrelated, b"other bytes")?;
    let unrelated_bundle = temp_dir.path().join("unrelated.bin.mkpe");
    create_mkpe_bundle(&unrelated, &keypair, &unrelated_bundle)?;

    let result = create_build_attestation(
        &subject,
        &keypair,
        AttestationOptions {
            bundle_path: Some(unrelated_bundle),
            ..AttestationOptions::default()
        },
    );

    assert!(matches!(
        result.unwrap_err(),
        MkpeError::VerificationFailed(_)
    ));

    Ok(())
}

#[test]
fn test_attestation_links_to_mkpe_bundle_identity() -> morse_kirby_core::Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let subject = temp_dir.path().join("release.bin");
    std::fs::write(&subject, b"release bytes")?;
    let bundle_path = temp_dir.path().join("release.bin.mkpe");
    let archive = create_mkpe_bundle(&subject, &keypair, &bundle_path)?;

    let attestation = create_build_attestation(
        &subject,
        &keypair,
        AttestationOptions {
            bundle_path: Some(bundle_path.clone()),
            ..AttestationOptions::default()
        },
    )?;

    assert_eq!(
        attestation.bundle_manifest_id.as_deref(),
        Some(archive.manifest.manifest_id.as_str())
    );
    assert_eq!(
        attestation.bundle_root_hash.as_deref(),
        Some(archive.manifest.bundle_root_hash.as_str())
    );

    let report = verify_build_attestation(
        &attestation,
        AttestationVerificationOptions {
            subject_path: Some(subject),
            trusted_public_key: Some(keypair.public_key),
            bundle_path: Some(bundle_path),
        },
    )?;

    assert_eq!(
        report.bundle_root_hash.as_deref(),
        Some(archive.manifest.bundle_root_hash.as_str())
    );

    Ok(())
}

#[test]
fn test_linked_attestation_requires_subject_for_verification() -> morse_kirby_core::Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let subject = temp_dir.path().join("release.bin");
    std::fs::write(&subject, b"release bytes")?;
    let bundle_path = temp_dir.path().join("release.bin.mkpe");
    create_mkpe_bundle(&subject, &keypair, &bundle_path)?;

    let attestation = create_build_attestation(
        &subject,
        &keypair,
        AttestationOptions {
            bundle_path: Some(bundle_path.clone()),
            ..AttestationOptions::default()
        },
    )?;

    let error = verify_build_attestation(
        &attestation,
        AttestationVerificationOptions {
            subject_path: None,
            trusted_public_key: Some(keypair.public_key),
            bundle_path: Some(bundle_path),
        },
    )
    .unwrap_err();

    assert!(matches!(error, MkpeError::VerificationFailed(_)));

    Ok(())
}

#[test]
fn test_directory_attestation_hash_is_deterministic() -> morse_kirby_core::Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let first = temp_dir.path().join("first");
    let second = temp_dir.path().join("second");
    std::fs::create_dir_all(first.join("nested"))?;
    std::fs::create_dir_all(second.join("nested"))?;
    std::fs::write(first.join("a.txt"), b"a")?;
    std::fs::write(first.join("nested").join("b.txt"), b"b")?;
    std::fs::write(second.join("nested").join("b.txt"), b"b")?;
    std::fs::write(second.join("a.txt"), b"a")?;

    let first_attestation =
        create_build_attestation(&first, &keypair, AttestationOptions::default())?;
    let second_attestation =
        create_build_attestation(&second, &keypair, AttestationOptions::default())?;

    assert_eq!(
        first_attestation.subject_sha256,
        second_attestation.subject_sha256
    );

    Ok(())
}
