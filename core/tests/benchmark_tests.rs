//! Performance benchmark tests for MKPE core operations.
//!
//! These benchmarks measure timing for key operations:
//! - Bundle creation (single file, 10, 100, 1000 files)
//! - Bundle loading and verification
//! - Directory hashing
//! - Merkle tree building
//! - Manifest signing
//! - File size handling

use morse_kirby_core::*;
use std::time::Instant;
use tempfile::TempDir;

/// Create a temporary file with the specified size in bytes.
fn create_temp_file(dir: &TempDir, name: &str, size_bytes: usize) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let data: Vec<u8> = (0..size_bytes).map(|i| (i % 256) as u8).collect();
    std::fs::write(&path, &data).expect("failed to write temp file");
    path
}

/// Create N temporary files in a directory, each with the specified size.
fn create_n_files(dir: &TempDir, count: usize, size_bytes: usize) -> std::path::PathBuf {
    let artifact_dir = dir.path().join("artifact");
    std::fs::create_dir(&artifact_dir).expect("failed to create artifact dir");
    for i in 0..count {
        let name = format!("file{:04}.dat", i);
        create_temp_file(&dir, artifact_dir.join(&name).to_str().unwrap(), size_bytes);
    }
    artifact_dir
}

// ============================================================================
// Bundle Creation Benchmarks
// ============================================================================

/// Benchmark bundling a single file.
#[test]
fn test_benchmark_single_file_bundle_creation() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let artifact_dir = create_n_files(&temp_dir, 1, 1024);

    let archive_path = temp_dir.path().join("single.mkpe");

    let start = Instant::now();
    let _archive = create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;
    let elapsed = start.elapsed();

    println!("Time for single file bundle creation: {:?}", elapsed);

    Ok(())
}

/// Benchmark bundling 10 files.
#[test]
fn test_benchmark_10_file_bundle_creation() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let artifact_dir = create_n_files(&temp_dir, 10, 1024);

    let archive_path = temp_dir.path().join("10files.mkpe");

    let start = Instant::now();
    let _archive = create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;
    let elapsed = start.elapsed();

    println!("Time for 10 file bundle creation: {:?}", elapsed);

    Ok(())
}

/// Benchmark bundling 100 files.
#[test]
fn test_benchmark_100_file_bundle_creation() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let artifact_dir = create_n_files(&temp_dir, 100, 1024);

    let archive_path = temp_dir.path().join("100files.mkpe");

    let start = Instant::now();
    let _archive = create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;
    let elapsed = start.elapsed();

    println!("Time for 100 file bundle creation: {:?}", elapsed);

    Ok(())
}

/// Benchmark bundling 1000 files (marked optional due to potential slowness).
#[test]
#[ignore]
fn test_benchmark_1000_file_bundle_creation() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let artifact_dir = create_n_files(&temp_dir, 1000, 512);

    let archive_path = temp_dir.path().join("1000files.mkpe");

    let start = Instant::now();
    let _archive = create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;
    let elapsed = start.elapsed();

    println!("Time for 1000 file bundle creation: {:?}", elapsed);

    Ok(())
}

/// Benchmark bundling an empty directory.
#[test]
fn test_benchmark_empty_directory_bundle_creation() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let artifact_dir = temp_dir.path().join("empty");
    std::fs::create_dir(&artifact_dir)?;

    let archive_path = temp_dir.path().join("empty.mkpe");

    let start = Instant::now();
    let _archive = create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;
    let elapsed = start.elapsed();

    println!("Time for empty directory bundle creation: {:?}", elapsed);

    Ok(())
}

// ============================================================================
// Bundle Loading / Verification Benchmarks
// ============================================================================

/// Benchmark loading and verifying a 10-file bundle.
#[test]
fn test_benchmark_10_file_bundle_load() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let artifact_dir = create_n_files(&temp_dir, 10, 1024);
    let archive_path = temp_dir.path().join("10files.mkpe");

    // Create the bundle first
    let _archive = create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;

    // Now benchmark load + verify
    let start = Instant::now();
    let loaded = MkpeArchive::load(&archive_path)?;
    let _verified = loaded.verify()?;
    let elapsed = start.elapsed();

    println!("Time for 10 file bundle load + verify: {:?}", elapsed);

    Ok(())
}

/// Benchmark loading and verifying a 100-file bundle.
#[test]
fn test_benchmark_100_file_bundle_load() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let artifact_dir = create_n_files(&temp_dir, 100, 1024);
    let archive_path = temp_dir.path().join("100files.mkpe");

    // Create the bundle first
    let _archive = create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;

    // Now benchmark load + verify
    let start = Instant::now();
    let loaded = MkpeArchive::load(&archive_path)?;
    let _verified = loaded.verify()?;
    let elapsed = start.elapsed();

    println!("Time for 100 file bundle load + verify: {:?}", elapsed);

    Ok(())
}

// ============================================================================
// Hashing Benchmarks
// ============================================================================

/// Benchmark hashing a directory with 10 files.
#[test]
fn test_benchmark_directory_hash_10_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = create_n_files(&temp_dir, 10, 1024);

    let start = Instant::now();
    let _hash = hash_subject(&artifact_dir)?;
    let elapsed = start.elapsed();

    println!("Time for directory hash (10 files): {:?}", elapsed);

    Ok(())
}

/// Benchmark hashing a directory with 100 files.
#[test]
fn test_benchmark_directory_hash_100_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let artifact_dir = create_n_files(&temp_dir, 100, 1024);

    let start = Instant::now();
    let _hash = hash_subject(&artifact_dir)?;
    let elapsed = start.elapsed();

    println!("Time for directory hash (100 files): {:?}", elapsed);

    Ok(())
}

// ============================================================================
// Merkle Tree Benchmarks
// ============================================================================

fn synthetic_hashes(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| format!("{:064x}", ((i as u64).wrapping_mul(0x123456789ABCDEF0u64))))
        .collect::<Vec<_>>()
}

/// Benchmark building a merkle root with 10 leaves.
#[test]
fn test_benchmark_merkle_tree_10_leaves() -> Result<()> {
    let hashes = synthetic_hashes(10);

    let start = Instant::now();
    let _root = build_merkle_root(&hashes);
    let elapsed = start.elapsed();

    println!("Time for merkle tree (10 leaves): {:?}", elapsed);

    Ok(())
}

/// Benchmark building a merkle root with 100 leaves.
#[test]
fn test_benchmark_merkle_tree_100_leaves() -> Result<()> {
    let hashes = synthetic_hashes(100);

    let start = Instant::now();
    let _root = build_merkle_root(&hashes);
    let elapsed = start.elapsed();

    println!("Time for merkle tree (100 leaves): {:?}", elapsed);

    Ok(())
}

/// Benchmark building a merkle root with 1000 leaves.
#[test]
fn test_benchmark_merkle_tree_1000_leaves() -> Result<()> {
    let hashes = synthetic_hashes(1000);

    let start = Instant::now();
    let _root = build_merkle_root(&hashes);
    let elapsed = start.elapsed();

    println!("Time for merkle tree (1000 leaves): {:?}", elapsed);

    Ok(())
}

// ============================================================================
// File Size Benchmarks
// ============================================================================

/// Benchmark bundling a single 1MB file.
#[test]
fn test_benchmark_1mb_file_bundling() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();

    let artifact_dir = temp_dir.path().join("artifact");
    std::fs::create_dir(&artifact_dir)?;
    create_temp_file(&temp_dir, artifact_dir.join("large.dat").to_str().unwrap(), 1024 * 1024);

    let archive_path = temp_dir.path().join("1mb.mkpe");

    let start = Instant::now();
    let _archive = create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;
    let elapsed = start.elapsed();

    println!("Time for 1MB file bundling: {:?}", elapsed);

    Ok(())
}

/// Benchmark bundling a single 10MB file (marked optional due to size).
#[test]
#[ignore]
fn test_benchmark_10mb_file_bundling() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();

    let artifact_dir = temp_dir.path().join("artifact");
    std::fs::create_dir(&artifact_dir)?;
    create_temp_file(
        &temp_dir,
        artifact_dir.join("large.dat").to_str().unwrap(),
        10 * 1024 * 1024,
    );

    let archive_path = temp_dir.path().join("10mb.mkpe");

    let start = Instant::now();
    let _archive = create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;
    let elapsed = start.elapsed();

    println!("Time for 10MB file bundling: {:?}", elapsed);

    Ok(())
}

/// Benchmark bundling 100 small files (1KB each).
#[test]
fn test_benchmark_100kb_many_small_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();

    let artifact_dir = create_n_files(&temp_dir, 100, 1024);
    let archive_path = temp_dir.path().join("100x1kb.mkpe");

    let start = Instant::now();
    let _archive = create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;
    let elapsed = start.elapsed();

    println!("Time for 100 x 1KB files bundling: {:?}", elapsed);

    Ok(())
}