//! Edge case tests for MKPE handling of empty, large, and special directory structures.
//!
//! These tests verify robust handling of:
//! - Empty artifacts and directories
//! - Large directory trees (many files, deep nesting, wide directories)
//! - Special files (zero-byte, symlinks, hidden files)
//! - Edge-case filenames (unicode, spaces, special characters, long paths)
//! - Deterministic ordering guarantees in proofs and hashes

use morse_kirby_core::*;
use tempfile::TempDir;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

// ============================================================================
// Empty Artifact Tests
// ============================================================================

/// Verifies that creating a bundle from an empty directory succeeds.
/// Empty directories are valid artifacts and should produce a minimal valid bundle.
#[test]
fn test_create_bundle_from_empty_directory() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("empty_artifact");
    fs::create_dir_all(&artifact_path)?;

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("empty.mkpe");

    create_mkpe_bundle(&artifact_path, &keypair, &archive_path)?;

    // Verify the archive loads correctly
    let archive = MkpeArchive::load(&archive_path)?;
    assert!(archive.verify().is_ok());

    Ok(())
}

/// Attestation of an empty directory should succeed.
/// An empty directory has a well-defined, deterministic hash.
#[test]
fn test_create_attestation_from_empty_directory() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("empty_dir");
    fs::create_dir_all(&artifact_path)?;

    let keypair = generate_keypair();
    let options = AttestationOptions::default();

    let attestation = create_build_attestation(&artifact_path, &keypair, options)?;

    // Attestation should be valid
    assert!(!attestation.subject_sha256.is_empty());
    assert_eq!(attestation.subject_kind, AttestationSubjectKind::Directory);

    Ok(())
}

/// Verifying a bundle created from an empty directory should succeed.
/// The verification process must handle empty artifacts gracefully.
#[test]
fn test_verify_empty_directory_bundle() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("empty_artifact");
    fs::create_dir_all(&artifact_path)?;

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("empty.mkpe");

    create_mkpe_bundle(&artifact_path, &keypair, &archive_path)?;

    let archive = MkpeArchive::load(&archive_path)?;
    let verified = archive.verify()?;
    assert!(verified.inner().manifest.manifest_id.len() > 0);

    Ok(())
}

// ============================================================================
// Large Directory Tests
// ============================================================================

/// Stress test: creating a bundle with 100 small files.
/// Ensures the system handles many files without performance degradation or errors.
#[test]
fn test_create_bundle_with_100_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("many_files");
    fs::create_dir_all(&artifact_path)?;

    // Create 100 small files with sequential content
    for i in 0..100 {
        let file_path = artifact_path.join(format!("file_{:03}.txt", i));
        let mut file = File::create(&file_path)?;
        writeln!(file, "Content of file {}", i)?;
    }

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("many_files.mkpe");

    create_mkpe_bundle(&artifact_path, &keypair, &archive_path)?;

    // Verify bundle is valid
    let archive = MkpeArchive::load(&archive_path)?;
    assert!(archive.verify().is_ok());

    Ok(())
}

/// Tests handling of deeply nested directory structures (10 levels deep).
/// Ensures recursive operations don't hit path length limits or stack overflow.
#[test]
fn test_create_bundle_with_deep_nesting() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("deep_nesting");
    fs::create_dir_all(&artifact_path)?;

    // Create 10-level deep directory structure
    let mut current = artifact_path.clone();
    for i in 0..10 {
        current = current.join(format!("level_{}", i));
    }
    fs::create_dir_all(&current)?;

    // Put a file at the deepest level
    let deep_file = current.join("deep_file.txt");
    File::create(&deep_file)?.write_all(b"deep content")?;

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("deep.mkpe");

    create_mkpe_bundle(&artifact_path, &keypair, &archive_path)?;

    let archive = MkpeArchive::load(&archive_path)?;
    assert!(archive.verify().is_ok());

    Ok(())
}

/// Tests handling of wide directories (50 sibling files in one directory).
/// Ensures ordering and iteration work correctly with many files at same level.
#[test]
fn test_create_bundle_with_wide_directory() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("wide_dir");
    fs::create_dir_all(&artifact_path)?;

    // Create 50 sibling files
    for i in 0..50 {
        let file_path = artifact_path.join(format!("sibling_{:02}.txt", i));
        File::create(&file_path)?.write_all(format!("sibling {}", i).as_bytes())?;
    }

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("wide.mkpe");

    create_mkpe_bundle(&artifact_path, &keypair, &archive_path)?;

    let archive = MkpeArchive::load(&archive_path)?;
    assert!(archive.verify().is_ok());

    Ok(())
}

/// Tests mixed content: files, empty directories, and nested directories together.
/// Verifies the system correctly handles heterogeneous directory structures.
#[test]
fn test_create_bundle_with_mixed_content() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("mixed");
    fs::create_dir_all(&artifact_path)?;

    // Create some files at root
    File::create(artifact_path.join("root_file.txt"))?.write_all(b"root")?;

    // Create empty directory
    fs::create_dir(artifact_path.join("empty_dir"))?;

    // Create nested structure with files
    let nested = artifact_path.join("nested/sub/deep");
    fs::create_dir_all(&nested)?;
    File::create(nested.join("nested_file.txt"))?.write_all(b"nested")?;

    // Create another sibling directory with content
    let sibling = artifact_path.join("sibling_dir");
    fs::create_dir_all(&sibling)?;
    File::create(sibling.join("file1.txt"))?.write_all(b"content1")?;
    File::create(sibling.join("file2.txt"))?.write_all(b"content2")?;

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("mixed.mkpe");

    create_mkpe_bundle(&artifact_path, &keypair, &archive_path)?;

    let archive = MkpeArchive::load(&archive_path)?;
    assert!(archive.verify().is_ok());

    Ok(())
}

// ============================================================================
// Special File Tests
// ============================================================================

/// Tests handling of zero-byte (empty) files.
/// These should be included in the bundle with zero length.
#[test]
fn test_create_bundle_with_zero_byte_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("zero_bytes");
    fs::create_dir_all(&artifact_path)?;

    // Create zero-byte files
    File::create(artifact_path.join("empty1.txt"))?;
    File::create(artifact_path.join("empty2.txt"))?;
    File::create(artifact_path.join("also_empty.log"))?;

    // Create one non-empty file for contrast
    File::create(artifact_path.join("non_empty.txt"))?.write_all(b"content")?;

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("zero_bytes.mkpe");

    create_mkpe_bundle(&artifact_path, &keypair, &archive_path)?;

    let archive = MkpeArchive::load(&archive_path)?;
    assert!(archive.verify().is_ok());

    Ok(())
}

/// Tests handling of symlinks within the artifact.
/// Symlinks should either be skipped gracefully or handled explicitly.
#[test]
fn test_create_bundle_with_symlink() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("symlink_test");
    let target_path = artifact_path.join("target_file.txt");
    let link_path = artifact_path.join("symlink_to_target");

    fs::create_dir_all(&artifact_path)?;
    File::create(&target_path)?.write_all(b"target content")?;

    #[cfg(unix)]
    std::os::unix::fs::symlink(&target_path, &link_path).ok();

    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&target_path, &link_path).ok();

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("symlink.mkpe");

    // Bundle creation should succeed (symlinks skipped or handled gracefully)
    let result = create_mkpe_bundle(&artifact_path, &keypair, &archive_path);
    assert!(result.is_ok());

    // If bundle was created, verify it loads
    if archive_path.exists() {
        let archive = MkpeArchive::load(&archive_path)?;
        assert!(archive.verify().is_ok());
    }

    Ok(())
}

/// Tests handling of hidden files (starting with dot).
/// Hidden files should be included in the bundle.
#[test]
fn test_create_bundle_with_hidden_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("hidden_test");
    fs::create_dir_all(&artifact_path)?;

    // Create hidden files
    File::create(artifact_path.join(".hidden_file"))?.write_all(b"hidden content")?;
    File::create(artifact_path.join(".env"))?.write_all(b"SECRET=value")?;
    File::create(artifact_path.join(".gitkeep"))?;

    // Create visible file for comparison
    File::create(artifact_path.join("visible.txt"))?.write_all(b"visible")?;

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("hidden.mkpe");

    create_mkpe_bundle(&artifact_path, &keypair, &archive_path)?;

    let archive = MkpeArchive::load(&archive_path)?;
    assert!(archive.verify().is_ok());

    Ok(())
}

/// Verifies that .mkpe files inside the artifact tree are handled correctly.
#[test]
fn test_create_bundle_ignores_dot_mkpe_inside_artifact() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("artifact");
    fs::create_dir_all(&artifact_path)?;

    // Create a legitimate file
    File::create(artifact_path.join("real_file.txt"))?.write_all(b"real content")?;

    // Create a .mkpe file that should be handled
    let dot_mkpe = artifact_path.join(".mkpe");
    File::create(&dot_mkpe)?.write_all(b"mkpe content")?;

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("test.mkpe");

    create_mkpe_bundle(&artifact_path, &keypair, &archive_path)?;

    let archive = MkpeArchive::load(&archive_path)?;
    assert!(archive.verify().is_ok());

    Ok(())
}

// ============================================================================
// Path Edge Cases
// ============================================================================

/// Tests handling of unicode filenames (non-ASCII characters).
/// Ensures proper encoding/decoding of international characters.
#[test]
fn test_create_bundle_with_unicode_filenames() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("unicode_test");
    fs::create_dir_all(&artifact_path)?;

    // Create files with unicode names
    File::create(artifact_path.join("日本語.txt"))?.write_all(b"japanese")?;
    File::create(artifact_path.join("файл.txt"))?.write_all(b"cyrillic")?;
    File::create(artifact_path.join("文件.txt"))?.write_all(b"chinese")?;
    File::create(artifact_path.join("émoji_🎉.txt"))?.write_all(b"emoji")?;
    File::create(artifact_path.join("José García.txt"))?.write_all(b"spanish")?;

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("unicode.mkpe");

    create_mkpe_bundle(&artifact_path, &keypair, &archive_path)?;

    let archive = MkpeArchive::load(&archive_path)?;
    assert!(archive.verify().is_ok());

    Ok(())
}

/// Tests handling of filenames with spaces.
/// Spaces are common in user-created files and should not break path parsing.
#[test]
fn test_create_bundle_with_spaces_in_paths() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("spaces_test");
    fs::create_dir_all(&artifact_path)?;

    // Create files with spaces
    File::create(artifact_path.join("file with spaces.txt"))?.write_all(b"spaces")?;
    File::create(artifact_path.join("  leading spaces.txt"))?.write_all(b"leading")?;
    File::create(artifact_path.join("trailing spaces  .txt"))?.write_all(b"trailing")?;

    // Create directory with spaces
    let dir_with_spaces = artifact_path.join("directory with spaces");
    fs::create_dir_all(&dir_with_spaces)?;
    File::create(dir_with_spaces.join("nested file.txt"))?.write_all(b"nested")?;

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("spaces.mkpe");

    create_mkpe_bundle(&artifact_path, &keypair, &archive_path)?;

    let archive = MkpeArchive::load(&archive_path)?;
    assert!(archive.verify().is_ok());

    Ok(())
}

/// Tests handling of very long filenames.
/// Ensures the system doesn't hit filename length limits unexpectedly.
#[test]
fn test_create_bundle_with_long_filenames() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("long_names");
    fs::create_dir_all(&artifact_path)?;

    // Create file with very long name (255 chars is typical limit, use less for safety)
    let long_name = "a".repeat(200);
    File::create(artifact_path.join(&long_name))?.write_all(b"long name")?;

    // Create file with long extension
    let long_ext = format!("file.{}", "x".repeat(100));
    File::create(artifact_path.join(long_ext))?.write_all(b"long extension")?;

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("long_names.mkpe");

    create_mkpe_bundle(&artifact_path, &keypair, &archive_path)?;

    let archive = MkpeArchive::load(&archive_path)?;
    assert!(archive.verify().is_ok());

    Ok(())
}

/// Tests handling of filenames with special characters.
#[test]
fn test_create_bundle_with_special_chars() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("special_chars");
    fs::create_dir_all(&artifact_path)?;

    // Create files with special characters (that are valid on most filesystems)
    File::create(artifact_path.join("file-with-dashes.txt"))?.write_all(b"dashes")?;
    File::create(artifact_path.join("file_with_underscores.txt"))?.write_all(b"underscores")?;
    File::create(artifact_path.join("file.multiple.dots.txt"))?.write_all(b"dots")?;
    File::create(artifact_path.join("file_with_parens(1).txt"))?.write_all(b"parens")?;
    File::create(artifact_path.join("file_with_brackets[1].txt"))?.write_all(b"brackets")?;

    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("special.mkpe");

    create_mkpe_bundle(&artifact_path, &keypair, &archive_path)?;

    let archive = MkpeArchive::load(&archive_path)?;
    assert!(archive.verify().is_ok());

    Ok(())
}

// ============================================================================
// Directory Proof Determinism
// ============================================================================

/// Verifies that proofs are sorted by path regardless of filesystem iteration order.
#[test]
fn test_proofs_sorted_regardless_of_fs_order() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_path = temp_dir.path().join("sort_test");
    fs::create_dir_all(&artifact_path)?;

    // Create files in non-alphabetical order to test sorting
    File::create(artifact_path.join("z_file.txt"))?.write_all(b"z")?;
    File::create(artifact_path.join("a_file.txt"))?.write_all(b"a")?;
    File::create(artifact_path.join("m_file.txt"))?.write_all(b"m")?;

    let keypair = generate_keypair();

    // Create proofs twice
    let proofs1 = create_recursive_proofs(&artifact_path, &keypair)?;
    let proofs2 = create_recursive_proofs(&artifact_path, &keypair)?;

    // Extract paths and compare
    let paths1: Vec<PathBuf> = proofs1.iter().map(|p| p.path.clone()).collect();
    let paths2: Vec<PathBuf> = proofs2.iter().map(|p| p.path.clone()).collect();

    // Paths should be identical and sorted
    assert_eq!(paths1, paths2);

    // Verify sorted order
    let mut sorted_paths = paths1.clone();
    sorted_paths.sort();
    assert_eq!(paths1, sorted_paths);

    Ok(())
}

/// Verifies that directory hash is independent of file ordering.
#[test]
fn test_directory_hash_order_independent() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let dir1 = temp_dir.path().join("dir1");
    let dir2 = temp_dir.path().join("dir2");

    fs::create_dir_all(&dir1)?;
    fs::create_dir_all(&dir2)?;

    // Create identical files in different order in each directory
    File::create(dir1.join("a.txt"))?.write_all(b"content_a")?;
    File::create(dir1.join("b.txt"))?.write_all(b"content_b")?;
    File::create(dir1.join("c.txt"))?.write_all(b"content_c")?;

    File::create(dir2.join("c.txt"))?.write_all(b"content_c")?;
    File::create(dir2.join("a.txt"))?.write_all(b"content_a")?;
    File::create(dir2.join("b.txt"))?.write_all(b"content_b")?;

    // Hash both directories
    let hash1 = hash_subject(&dir1)?;
    let hash2 = hash_subject(&dir2)?;

    // Hashes should be identical regardless of creation order
    assert_eq!(hash1, hash2, "Directory hash should be independent of file creation order");

    Ok(())
}