//! Encoding and cross-platform path handling tests for MKPE.

use morse_kirby_core::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_canonical_path_uses_forward_slash() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let nested = temp_dir.path().join("a").join("b").join("file.txt");
    fs::create_dir_all(nested.parent().unwrap())?;
    fs::write(&nested, b"content")?;
    let hash = hash_subject(nested.parent().unwrap())?;
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    Ok(())
}

#[test]
fn test_directory_hash_uses_forward_slash_in_paths() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let subdir = temp_dir.path().join("src").join("utils");
    fs::create_dir_all(&subdir)?;
    fs::write(subdir.join("mod.rs"), b"// source")?;
    fs::write(temp_dir.path().join("README.md"), b"# doc")?;
    let hash = hash_subject(temp_dir.path())?;
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    let hash2 = hash_subject(temp_dir.path())?;
    assert_eq!(hash, hash2);
    Ok(())
}

#[test]
fn test_proof_paths_normalized_to_relative() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(artifact_dir.join("nested").join("deep"))?;
    fs::write(artifact_dir.join("root.txt"), b"root")?;
    fs::write(artifact_dir.join("nested").join("deep").join("leaf.txt"), b"leaf")?;
    let keypair = generate_keypair();
    let proofs = create_recursive_proofs(&artifact_dir, &keypair)?;
    for proof in &proofs {
        let path_str = proof.path.to_string_lossy();
        assert!(!path_str.starts_with('/'), "Proof path '{}' should not start with '/'", path_str);
        assert!(!path_str.starts_with('\\'), "Proof path '{}' should not start with '\\'", path_str);
        if path_str.contains('/') {
            assert!(!path_str.starts_with('/'), "Nested path '{}' should not start with '/'", path_str);
        }
    }
    Ok(())
}

#[test]
fn test_binary_bundle_roundtrip_preserves_all_bytes() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_dir)?;
    fs::write(artifact_dir.join("data.bin"), b"\x00\xff\xfe\xfd\xfc\x01\x02\x03")?;
    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("roundtrip.mkpe");
    create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;
    let archive = MkpeArchive::load(&archive_path)?;
    assert!(archive.verify_artifact_with_public_key(&artifact_dir, &keypair.public_key)?.verified_proofs > 0);
    let raw_bytes = fs::read(&archive_path)?;
    assert_eq!(&raw_bytes[0..4], b"MKPE", "Header magic should be preserved");
    assert_eq!(&raw_bytes[raw_bytes.len() - 8..raw_bytes.len() - 4], b"EPKM", "Footer magic should be preserved");
    Ok(())
}

#[test]
fn test_manifest_json_roundtrip_preserves_data() -> Result<()> {
    let keypair = generate_keypair();
    let mut manifest = Manifest::new("abc123".to_string(), 42, keypair.public_key.clone(), None);
    manifest.add_metadata("key".to_string(), serde_json::json!("value"));
    manifest.sign(&keypair)?;
    let json_bytes = serde_json::to_vec(&manifest)?;
    let manifest_loaded: Manifest = serde_json::from_slice(&json_bytes)?;
    assert_eq!(manifest.manifest_id, manifest_loaded.manifest_id);
    assert_eq!(manifest.bundle_root_hash, manifest_loaded.bundle_root_hash);
    assert_eq!(manifest.proof_count, manifest_loaded.proof_count);
    assert_eq!(manifest.verifier_public_key, manifest_loaded.verifier_public_key);
    assert_eq!(manifest.signature, manifest_loaded.signature);
    Ok(())
}

#[test]
fn test_proof_section_json_roundtrip() -> Result<()> {
    let temp_dir = TempDir::new()?;
    fs::write(temp_dir.path().join("a.txt"), b"file A")?;
    fs::write(temp_dir.path().join("b.txt"), b"file B")?;
    let keypair = generate_keypair();
    let proofs = create_recursive_proofs(temp_dir.path(), &keypair)?;
    let bundle = create_proof_bundle(proofs.clone(), &keypair, None)?;
    let proof_bytes = serde_json::to_vec(&[&bundle])?;
    let loaded: Vec<ProofBundle> = serde_json::from_slice(&proof_bytes)?;
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].bundle_id, bundle.bundle_id);
    assert_eq!(loaded[0].root_hash, bundle.root_hash);
    assert_eq!(loaded[0].proofs.len(), bundle.proofs.len());
    for (orig, loaded_item) in bundle.proofs.iter().zip(loaded[0].proofs.iter()) {
        assert_eq!(orig.id, loaded_item.id);
        assert_eq!(orig.content_hash, loaded_item.content_hash);
        assert_eq!(orig.path, loaded_item.path);
    }
    Ok(())
}

#[test]
fn test_unicode_in_filenames_preserved() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_dir)?;
    let unicode_files = ["café.txt", "日本語.txt", "Ärger.txt", "🎮game.txt"];
    for filename in unicode_files {
        let path = artifact_dir.join(filename);
        fs::write(&path, format!("content of {}", filename))?;
    }
    let keypair = generate_keypair();
    let proofs = create_recursive_proofs(&artifact_dir, &keypair)?;
    assert_eq!(proofs.len(), unicode_files.len());
    for proof in &proofs {
        let path_str = proof.path.to_string_lossy();
        let is_unicode = path_str.chars().any(|c| !c.is_ascii());
        assert!(is_unicode, "Proof path '{}' should preserve Unicode characters", path_str);
    }
    Ok(())
}

#[test]
fn test_utf8_content_preserved_in_bundle() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_dir)?;
    let utf8_content = "Hello 世界 🌍\nGrüße\n日本語フォント";
    fs::write(artifact_dir.join("utf8.txt"), utf8_content)?;
    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("utf8.mkpe");
    create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;
    let report = MkpeArchive::load(&archive_path)?
        .verify_artifact_with_public_key(&artifact_dir, &keypair.public_key)?;
    assert_eq!(report.verified_proofs, 1);
    Ok(())
}

#[test]
fn test_ascii_only_content_preserved() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_dir)?;
    let ascii_content = "All ASCII characters: !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    fs::write(artifact_dir.join("ascii.txt"), ascii_content)?;
    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("ascii.mkpe");
    create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;
    let report = MkpeArchive::load(&archive_path)?
        .verify_artifact_with_public_key(&artifact_dir, &keypair.public_key)?;
    assert_eq!(report.verified_proofs, 1);
    Ok(())
}

#[test]
fn test_binary_content_preserved_in_bundle() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_dir)?;
    let binary_content: Vec<u8> = (0u8..=255u8).collect();
    fs::write(artifact_dir.join("binary.bin"), &binary_content)?;
    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("binary.mkpe");
    create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;
    let report = MkpeArchive::load(&archive_path)?
        .verify_artifact_with_public_key(&artifact_dir, &keypair.public_key)?;
    assert_eq!(report.verified_proofs, 1);
    let raw_bytes = fs::read(artifact_dir.join("binary.bin"))?;
    assert_eq!(raw_bytes, (0u8..=255u8).collect::<Vec<u8>>());
    Ok(())
}

#[test]
fn test_relative_path_no_leading_separator() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("project");
    fs::create_dir_all(artifact_dir.join("src").join("lib"))?;
    fs::write(artifact_dir.join("src").join("lib").join("mod.rs"), b"mod content")?;
    let keypair = generate_keypair();
    let proofs = create_recursive_proofs(&artifact_dir, &keypair)?;
    for proof in &proofs {
        let path_str = proof.path.to_string_lossy();
        assert!(!path_str.starts_with('/'), "Path '{}' should not start with '/'", path_str);
        assert!(!path_str.starts_with('\\'), "Path '{}' should not start with '\\'", path_str);
        if path_str.len() >= 2 {
            assert!(path_str.chars().nth(1) != Some(':'), "Path '{}' should not contain a drive letter prefix", path_str);
        }
    }
    Ok(())
}

#[test]
fn test_proof_path_no_absolute_prefix() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_dir)?;
    fs::create_dir_all(artifact_dir.join("nested"))?;
    fs::write(artifact_dir.join("nested").join("file.txt"), b"content")?;
    let keypair = generate_keypair();
    let proofs = create_recursive_proofs(&artifact_dir, &keypair)?;
    let bundle = create_proof_bundle(proofs, &keypair, None)?;
    for proof in &bundle.proofs {
        let path_str = proof.path.to_string_lossy();
        assert!(!path_str.starts_with('/'), "Bundle proof path '{}' must be relative, not absolute", path_str);
        if path_str.len() >= 2 {
            assert!(path_str.chars().nth(1) != Some(':'), "Bundle proof path '{}' must not have a Windows drive prefix", path_str);
        }
        assert!(!path_str.is_empty(), "Proof path '{}' must not be empty", path_str);
    }
    Ok(())
}

#[test]
fn test_manifest_path_handles_unicode() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("café_project");
    fs::create_dir_all(&artifact_dir)?;
    fs::write(artifact_dir.join("日本語.txt"), b"content")?;
    let keypair = generate_keypair();
    let proofs = create_recursive_proofs(&artifact_dir, &keypair)?;
    let bundle = create_proof_bundle(proofs, &keypair, None)?;
    let mut manifest = Manifest::new(bundle.root_hash.clone(), bundle.proofs.len(), keypair.public_key.clone(), None);
    manifest.add_metadata("unicode_file".to_string(), serde_json::json!("café_project/日本語.txt"));
    manifest.sign(&keypair)?;
    let json = serde_json::to_vec(&manifest)?;
    let loaded: Manifest = serde_json::from_slice(&json)?;
    assert_eq!(manifest.manifest_id, loaded.manifest_id);
    assert!(loaded.metadata.get("unicode_file").is_some());
    assert!(loaded.verify()?);
    let archive_path = temp_dir.path().join("unicode.mkpe");
    let manifest_id = manifest.manifest_id.clone();
    let archive = MkpeArchive::new(manifest, vec![bundle]);
    archive.save(&archive_path, &keypair)?;
    let loaded_archive = MkpeArchive::load(&archive_path)?;
    assert_eq!(loaded_archive.manifest.manifest_id, manifest_id);
    assert!(loaded_archive.manifest.verify()?);
    Ok(())
}

#[test]
fn test_json_manifest_no_trailing_whitespace() -> Result<()> {
    let keypair = generate_keypair();
    let mut manifest = Manifest::new("test_hash".to_string(), 10, keypair.public_key.clone(), None);
    manifest.add_metadata("note".to_string(), serde_json::json!("test"));
    manifest.sign(&keypair)?;
    let json_bytes = serde_json::to_vec(&manifest)?;
    let json_str = String::from_utf8(json_bytes.clone())
        .map_err(|_| MkpeError::BundleError("Manifest JSON should be valid UTF-8".to_string()))?;
    for (i, line) in json_str.lines().enumerate() {
        assert_eq!(line.trim_end().len(), line.len(), "Line {} has trailing whitespace: '{}'", i + 1, line);
    }
    let trimmed = json_str.trim();
    assert_eq!(json_str, trimmed, "JSON should have no leading or trailing whitespace");
    let reparsed: Manifest = serde_json::from_slice(&json_bytes)?;
    assert_eq!(reparsed.manifest_id, manifest.manifest_id);
    Ok(())
}

#[test]
fn test_base64_keys_are_standard_alphabet() -> Result<()> {
    let keypair = generate_keypair();
    for key_str in [&keypair.private_key, &keypair.public_key] {
        assert!(!key_str.contains('-'), "Key should use standard Base64, not URL-safe (-)");
        assert!(!key_str.contains('_'), "Key should use standard Base64, not URL-safe (_)");
        for c in key_str.chars() {
            assert!(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=', "Key contains invalid Base64 character: {}", c);
        }
    }
    Ok(())
}

#[test]
fn test_hex_hashes_are_lowercase() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_dir)?;
    fs::write(artifact_dir.join("test.txt"), b"test content")?;
    let keypair = generate_keypair();
    let proofs = create_recursive_proofs(&artifact_dir, &keypair)?;
    for proof in &proofs {
        assert_eq!(proof.content_hash.len(), 64);
        assert!(proof.content_hash.chars().all(|c| c.is_ascii_hexdigit()), "Hash '{}' should be valid hex", proof.content_hash);
    }
    let bundle = create_proof_bundle(proofs, &keypair, None)?;
    assert_eq!(bundle.root_hash.len(), 64);
    assert!(bundle.root_hash.chars().all(|c| c.is_ascii_hexdigit()), "Merkle root '{}' should be valid hex", bundle.root_hash);
    Ok(())
}