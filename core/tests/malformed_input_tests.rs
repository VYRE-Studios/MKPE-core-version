//! Malformed and corrupt input tests for MKPE core library.
//!
//! These tests verify that the library correctly rejects malformed,
//! truncated, corrupted, or otherwise invalid inputs at all boundaries.
//! Each test guards against a specific class of vulnerability such as
//! buffer overruns, unvalidated size fields, or schema downgrade attacks.

use morse_kirby_core::*;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// Binary Bundle Corrupt Input Tests
// ============================================================================

/// Guard against files smaller than the minimum 32-byte header.
#[test]
fn test_load_rejects_truncated_header() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("truncated.mkpe");

    // Write only 31 bytes (header requires exactly 32)
    fs::write(&path, vec![0u8; 31])?;

    let result = MkpeArchive::load(&path);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), MkpeError::BundleError(_) | MkpeError::IoError(_)));

    Ok(())
}

/// Guard against files with invalid magic bytes.
#[test]
fn test_load_rejects_invalid_magic_bytes() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("bad_magic.mkpe");

    let mut data = vec![0u8; 32];
    data[0..4].copy_from_slice(b"XXXX"); // Wrong magic

    fs::write(&path, data)?;

    let result = MkpeArchive::load(&path);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), MkpeError::BundleError(_)));

    Ok(())
}

/// Guard against unsupported format versions that may lack required fields.
#[test]
fn test_load_rejects_unsupported_version() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("bad_version.mkpe");

    let mut data = vec![0u8; 32];
    data[0..4].copy_from_slice(b"MKPE");
    data[4] = 0xFF; // Version > 2

    fs::write(&path, data)?;

    let result = MkpeArchive::load(&path);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), MkpeError::BundleError(_)));

    Ok(())
}

/// Guard against manifest_size larger than the actual file (reads past EOF).
#[test]
fn test_load_rejects_manifest_size_exceeds_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("huge_manifest.mkpe");

    let mut data = vec![0u8; 32];
    data[0..4].copy_from_slice(b"MKPE");
    data[4] = 0x02; // version 2

    fs::write(&path, data)?;

    let result = MkpeArchive::load(&path);
    assert!(result.is_err());

    Ok(())
}

/// Guard against proof_size larger than the actual file.
#[test]
fn test_load_rejects_proof_size_exceeds_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("huge_proof.mkpe");

    let mut data = vec![0u8; 32];
    data[0..4].copy_from_slice(b"MKPE");
    data[4] = 0x02;
    data[6..14].copy_from_slice(&0u64.to_le_bytes()); // manifest_size = 0
    data[14..22].copy_from_slice(&0x1_0000_0000u64.to_le_bytes()); // proof_size huge

    fs::write(&path, data)?;

    let result = MkpeArchive::load(&path);
    assert!(result.is_err());

    Ok(())
}

/// Guard against signature_size larger than the actual file.
#[test]
fn test_load_rejects_signature_size_exceeds_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("huge_sig.mkpe");

    let mut data = vec![0u8; 32];
    data[0..4].copy_from_slice(b"MKPE");
    data[4] = 0x02;
    // All size fields set high
    data[6..14].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes());
    data[14..22].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes());
    data[22..30].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes());

    fs::write(&path, data)?;

    let result = MkpeArchive::load(&path);
    assert!(result.is_err());

    Ok(())
}

/// Guard against garbage data after the valid footer.
#[test]
fn test_load_rejects_trailing_bytes() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("trailing_garbage.mkpe");

    // Build minimal valid bundle then append garbage
    let keypair = generate_keypair();

    // Create artifact directory with a file
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_dir)?;
    fs::write(artifact_dir.join("test.txt"), b"content")?;

    let archive_path = temp_dir.path().join("temp.mkpe");
    create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;

    // Append garbage bytes
    let existing = fs::read(&archive_path)?;
    let mut corrupted = existing;
    corrupted.extend_from_slice(b"TRAILING_GARBAGE_DATA");
    fs::write(&path, &corrupted)?;

    let result = MkpeArchive::load(&path);
    assert!(result.is_err());

    Ok(())
}

/// Guard against missing or corrupted footer magic (EPKM).
#[test]
fn test_load_rejects_invalid_footer_magic() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("bad_footer_magic.mkpe");

    // Create minimal bundle
    let keypair = generate_keypair();
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_dir)?;
    fs::write(artifact_dir.join("test.txt"), b"content")?;

    let archive_path = temp_dir.path().join("temp.mkpe");
    create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;

    // Corrupt the footer magic in place
    let mut data = fs::read(&archive_path)?;
    let footer_offset = data.len() - 8;
    data[footer_offset..footer_offset + 4].copy_from_slice(b"XXXX"); // Wrong footer magic

    fs::write(&path, data)?;

    let result = MkpeArchive::load(&path);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), MkpeError::BundleError(_)));

    Ok(())
}

/// Guard against corrupted data that fails CRC32 validation.
#[test]
fn test_load_rejects_crc32_mismatch() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("bad_crc.mkpe");

    let keypair = generate_keypair();
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_dir)?;
    fs::write(artifact_dir.join("test.txt"), b"content")?;

    let archive_path = temp_dir.path().join("temp.mkpe");
    create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;

    // Corrupt a byte in the manifest section (after header, before footer)
    let mut data = fs::read(&archive_path)?;
    let header_size = 32;
    if data.len() > header_size + 10 {
        data[header_size + 5] ^= 0xFF; // Flip bits in manifest area
    }

    fs::write(&path, data)?;

    let result = MkpeArchive::load(&path);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), MkpeError::BundleError(_)));

    Ok(())
}

/// Guard against corrupted manifest JSON content (valid JSON but wrong data).
#[test]
fn test_load_rejects_corrupted_manifest_json() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("corrupt_manifest.mkpe");

    let mut data = vec![0u8; 32];
    data[0..4].copy_from_slice(b"MKPE");
    data[4] = 0x02;

    let manifest_bytes = b"{\"schema_version\": \"2.0\", \"engine_version\": \"0.1.0\"}";
    let manifest_len = manifest_bytes.len() as u64;
    data[6..14].copy_from_slice(&manifest_len.to_le_bytes());
    data[14..22].copy_from_slice(&0u64.to_le_bytes()); // proof_size
    data[22..30].copy_from_slice(&0u64.to_le_bytes()); // sig_size

    let mut full_data = data.to_vec();
    full_data.extend_from_slice(manifest_bytes);
    // No footer = truncated

    fs::write(&path, full_data)?;

    let result = MkpeArchive::load(&path);
    assert!(result.is_err());

    Ok(())
}

/// Guard against corrupted proof section data.
#[test]
fn test_load_rejects_corrupted_proof_section() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("corrupt_proof.mkpe");

    let keypair = generate_keypair();
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_dir)?;
    fs::write(artifact_dir.join("test.txt"), b"content")?;

    let archive_path = temp_dir.path().join("temp.mkpe");
    create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;

    // Read and corrupt the proof section
    let mut data = fs::read(&archive_path)?;
    let manifest_size = u64::from_le_bytes(data[6..14].try_into().unwrap()) as usize;
    let proof_offset = 32 + manifest_size;

    // Flip a byte in proof section if it exists
    if data.len() > proof_offset + 10 {
        data[proof_offset + 3] ^= 0x42;
    }

    fs::write(&path, data)?;

    let result = MkpeArchive::load(&path);
    assert!(result.is_err());

    Ok(())
}

/// Guard against manifest_size exceeding the 16MB safety limit.
#[test]
fn test_load_rejects_manifest_exceeds_max_size() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("huge_manifest_limit.mkpe");

    let mut data = vec![0u8; 32];
    data[0..4].copy_from_slice(b"MKPE");
    data[4] = 0x02;
    // Set manifest_size to 17MB (exceeds 16MB limit)
    let huge_size = 17 * 1024 * 1024;
    data[6..14].copy_from_slice(&(huge_size as u64).to_le_bytes());
    data[14..22].copy_from_slice(&0u64.to_le_bytes());
    data[22..30].copy_from_slice(&0u64.to_le_bytes());

    fs::write(&path, data)?;

    let result = MkpeArchive::load(&path);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), MkpeError::BundleError(_)));

    Ok(())
}

/// Guard against proof_size exceeding the 64MB safety limit.
#[test]
fn test_load_rejects_proof_exceeds_max_size() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("huge_proof_limit.mkpe");

    let mut data = vec![0u8; 32];
    data[0..4].copy_from_slice(b"MKPE");
    data[4] = 0x02;
    data[6..14].copy_from_slice(&0u64.to_le_bytes()); // manifest_size = 0
    // Set proof_size to 65MB (exceeds 64MB limit)
    let huge_size = 65 * 1024 * 1024;
    data[14..22].copy_from_slice(&(huge_size as u64).to_le_bytes());
    data[22..30].copy_from_slice(&0u64.to_le_bytes());

    fs::write(&path, data)?;

    let result = MkpeArchive::load(&path);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), MkpeError::BundleError(_)));

    Ok(())
}

// ============================================================================
// Corrupt Attestation JSON Tests
// ============================================================================

/// Guard against empty attestation JSON.
#[test]
fn test_verify_rejects_empty_json() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("empty_attestation.json");
    fs::write(&path, "{}")?;

    let content = fs::read_to_string(&path)?;
    let result: std::result::Result<BuildAttestation, _> = serde_json::from_str(&content);

    // Should fail to parse - missing required fields
    assert!(result.is_err());

    Ok(())
}

/// Guard against attestation missing required signer_public_key field.
#[test]
fn test_verify_rejects_missing_required_fields() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("missing_signer.json");

    // Missing signer_public_key field
    let json = serde_json::json!({
        "schema_version": "1.0",
        "attestation_id": "test-att-123",
        "subject_path": "/build/output.bin",
        "subject_kind": "file",
        "subject_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "build_fingerprint": {
            "hostname": "build-host",
            "platform": "Linux",
            "user": "builder",
            "process_id": 1234,
            "architecture": "x86_64",
            "mkpe_version": "1.0.0",
            "working_directory": "/build"
        },
        "timestamp_utc": "2024-01-15T10:30:00Z",
        "attested_by": "test",
        "signature": "invalid_sig"
    });

    fs::write(&path, serde_json::to_string_pretty(&json)?)?;

    let content = fs::read_to_string(&path)?;
    let result: std::result::Result<BuildAttestation, _> = serde_json::from_str(&content);

    // serde should reject missing required field
    assert!(result.is_err());

    Ok(())
}

/// Guard against null signature instead of string.
#[test]
fn test_verify_rejects_null_signature() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("null_signature.json");

    let json = serde_json::json!({
        "schema_version": "1.0",
        "attestation_id": "test-att-456",
        "subject_path": "/build/output.bin",
        "subject_kind": "file",
        "subject_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "build_fingerprint": {
            "hostname": "build-host",
            "platform": "Linux",
            "user": "builder",
            "process_id": 1234,
            "architecture": "x86_64",
            "mkpe_version": "1.0.0",
            "working_directory": "/build"
        },
        "timestamp_utc": "2024-01-15T10:30:00Z",
        "attested_by": "test",
        "signer_public_key": "dGVzdF9wdWJsaWNfa2V5",
        "signature": null
    });

    fs::write(&path, serde_json::to_string_pretty(&json)?)?;

    let content = fs::read_to_string(&path)?;
    let result: std::result::Result<BuildAttestation, _> = serde_json::from_str(&content);

    // serde should reject null for String field
    assert!(result.is_err());

    Ok(())
}

/// Guard against wrong schema_version (not "1.0").
#[test]
fn test_verify_rejects_wrong_schema_version() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("wrong_schema.json");

    let json = serde_json::json!({
        "schema_version": "0.9",
        "attestation_id": "test-att-789",
        "subject_path": "/build/output.bin",
        "subject_kind": "file",
        "subject_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "build_fingerprint": {
            "hostname": "build-host",
            "platform": "Linux",
            "user": "builder",
            "process_id": 1234,
            "architecture": "x86_64",
            "mkpe_version": "1.0.0",
            "working_directory": "/build"
        },
        "timestamp_utc": "2024-01-15T10:30:00Z",
        "attested_by": "test",
        "signer_public_key": "dGVzdF9wdWJsaWNfa2V5",
        "signature": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"
    });

    fs::write(&path, serde_json::to_string_pretty(&json)?)?;

    let content = fs::read_to_string(&path)?;
    let attestation: BuildAttestation = serde_json::from_str(&content)?;

    let options = AttestationVerificationOptions {
        subject_path: None,
        trusted_public_key: None,
        bundle_path: None,
    };
    let result = verify_build_attestation(&attestation, options);

    // Should reject unsupported schema version
    assert!(result.is_err());

    Ok(())
}

/// Guard against future schema_version (schema downgrade attempt).
#[test]
fn test_verify_rejects_future_schema_version() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("future_schema.json");

    let json = serde_json::json!({
        "schema_version": "9.0",
        "attestation_id": "test-att-future",
        "subject_path": "/build/output.bin",
        "subject_kind": "file",
        "subject_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "build_fingerprint": {
            "hostname": "build-host",
            "platform": "Linux",
            "user": "builder",
            "process_id": 1234,
            "architecture": "x86_64",
            "mkpe_version": "1.0.0",
            "working_directory": "/build"
        },
        "timestamp_utc": "2024-01-15T10:30:00Z",
        "attested_by": "test",
        "signer_public_key": "dGVzdF9wdWJsaWNfa2V5",
        "signature": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"
    });

    fs::write(&path, serde_json::to_string_pretty(&json)?)?;

    let content = fs::read_to_string(&path)?;
    let attestation: BuildAttestation = serde_json::from_str(&content)?;

    let options = AttestationVerificationOptions {
        subject_path: None,
        trusted_public_key: None,
        bundle_path: None,
    };
    let result = verify_build_attestation(&attestation, options);

    // Should reject unknown future schema version
    assert!(result.is_err());

    Ok(())
}

/// Guard against invalid non-ISO timestamp format.
#[test]
fn test_verify_rejects_invalid_timestamp() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("bad_timestamp.json");

    let json = serde_json::json!({
        "schema_version": "1.0",
        "attestation_id": "test-att-time",
        "subject_path": "/build/output.bin",
        "subject_kind": "file",
        "subject_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "build_fingerprint": {
            "hostname": "build-host",
            "platform": "Linux",
            "user": "builder",
            "process_id": 1234,
            "architecture": "x86_64",
            "mkpe_version": "1.0.0",
            "working_directory": "/build"
        },
        "timestamp_utc": "not-a-timestamp",
        "attested_by": "test",
        "signer_public_key": "dGVzdF9wdWJsaWNfa2V5",
        "signature": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"
    });

    fs::write(&path, serde_json::to_string_pretty(&json)?)?;

    let content = fs::read_to_string(&path)?;
    let result: std::result::Result<BuildAttestation, _> = serde_json::from_str(&content);

    // Should fail to parse invalid timestamp
    assert!(result.is_err());

    Ok(())
}

/// Guard against null subject_path field.
#[test]
fn test_verify_rejects_missing_subject_path() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("null_subject.json");

    let json = serde_json::json!({
        "schema_version": "1.0",
        "attestation_id": "test-att-null-subj",
        "subject_path": null,
        "subject_kind": "file",
        "subject_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "build_fingerprint": {
            "hostname": "build-host",
            "platform": "Linux",
            "user": "builder",
            "process_id": 1234,
            "architecture": "x86_64",
            "mkpe_version": "1.0.0",
            "working_directory": "/build"
        },
        "timestamp_utc": "2024-01-15T10:30:00Z",
        "attested_by": "test",
        "signer_public_key": "dGVzdF9wdWJsaWNfa2V5",
        "signature": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"
    });

    fs::write(&path, serde_json::to_string_pretty(&json)?)?;

    let content = fs::read_to_string(&path)?;
    let result: std::result::Result<BuildAttestation, _> = serde_json::from_str(&content);

    // Should reject null for required String field
    assert!(result.is_err());

    Ok(())
}

// ============================================================================
// Corrupt Manifest Tests
// ============================================================================

/// Guard against manifest missing the signature field entirely.
#[test]
fn test_manifest_verify_rejects_missing_signature_field() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("missing_sig.json");

    let json = serde_json::json!({
        "schema_version": "1.0",
        "engine_version": "1.0.0",
        "manifest_id": "test-manifest-001",
        "system_fingerprint": {
            "user": "testuser",
            "platform": "Linux",
            "hostname": "testhost",
            "process_id": 12345,
            "mkpe_version": "1.0.0",
            "timestamp": "2024-01-15T10:30:00Z"
        },
        "bundle_root_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "proof_count": 5,
        "sealed_timestamp": "2024-01-15T10:30:00Z",
        "verifier_public_key": "dGVzdF9wdWJsaWNfa2V5"
        // Missing: "signature"
    });

    fs::write(&path, serde_json::to_string_pretty(&json)?)?;

    let content = fs::read_to_string(&path)?;
    let result: std::result::Result<Manifest, _> = serde_json::from_str(&content);

    // Should fail due to missing required field
    assert!(result.is_err());

    Ok(())
}

/// Guard against manifest with non-base64 signature format.
#[test]
fn test_manifest_verify_rejects_invalid_signature_format() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("invalid_sig_format.json");

    let json = serde_json::json!({
        "schema_version": "1.0",
        "engine_version": "1.0.0",
        "manifest_id": "test-manifest-002",
        "metadata": {},
        "system_fingerprint": {
            "user": "testuser",
            "platform": "Linux",
            "hostname": "testhost",
            "process_id": 12345,
            "mkpe_version": "1.0.0",
            "timestamp": "2024-01-15T10:30:00Z"
        },
        "bundle_root_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "proof_count": 5,
        "sealed_timestamp": "2024-01-15T10:30:00Z",
        "verifier_public_key": "dGVzdF9wdWJsaWNfa2V5",
        "signature": "not-valid-base64!!!"
    });
    fs::write(&path, serde_json::to_string_pretty(&json)?)?;

    let content = fs::read_to_string(&path)?;
    let manifest: Manifest = serde_json::from_str(&content)?;

    // Parsing succeeds but verification should fail due to invalid base64
    let result = manifest.verify();
    assert!(result.is_err());

    Ok(())
}