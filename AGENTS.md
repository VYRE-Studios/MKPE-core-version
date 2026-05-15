## Learned User Preferences

- Tests must verify behavior, not just compilation success
- Industry-standard provenance tests (Sigstore, CAliPO, in-toto, TUF patterns) are desired
- Prefer detailed, descriptive test names that document expected behavior
- Document known limitations rather than silently failing

## Learned Workspace Facts

- MKPE is positioned as DNA tagging provenance for every byte created: a trust engine that proves artifacts are authentic, unchanged, and traceable.
- MKPE is a Rust-based cryptographic provenance system centered on `.mkpe` bundles with SHA-256 content proofs, Ed25519 signatures, manifests, CLI tooling, Windows-oriented service/UI layers, and future attestation/steganography layers.

## Test Patterns & Conventions

### Test File Organization
- Unit tests live in `core/src/` alongside the code they test
- Integration tests live in `core/tests/` subdirectory
- CLI tests live in `cli/tests/`

### Test Naming Conventions
- `test_<feature>_<expected_behavior>` - e.g., `test_load_rejects_invalid_magic_bytes`
- `test_<operation>_<handles_<edge_case>` - e.g., `test_empty_directory_handling`
- Document non-determinism with `#[ignore]` and explanation: `#[ignore = "reason"]`

### Common Test Patterns

#### TempDir with nested files
```rust
// CORRECT: Create parent directory first
fs::create_dir_all(artifact_dir.join("nested"))?;  // creates both
fs::write(artifact_dir.join("nested").join("file.txt"), b"content")?;

// INCORRECT (causes IoError):
fs::create_dir_all(&artifact_dir)?;
fs::write(artifact_dir.join("nested").join("file.txt"), b"content")?;
```

#### Verifying file content preserved
```rust
let report = MkpeArchive::load(&archive_path)?
    .verify_artifact_with_public_key(&artifact_dir, &keypair.public_key)?;
assert_eq!(report.verified_proofs, expected_count);
```

#### JSON serialization round-trip
```rust
let json_bytes = serde_json::to_vec(&manifest)?;
let loaded: Manifest = serde_json::from_slice(&json_bytes)?;
assert_eq!(manifest.manifest_id, loaded.manifest_id);
```

### Known Non-Deterministic Behaviors (Documented in Tests)

1. **Merkle tree ordering**: `build_merkle_root` depends on input order; tests marked `#[ignore]`
2. **Signature non-determinism**: JSON manifests include timestamps; signatures vary per invocation
3. **UUID generation**: `manifest_id` uses `Uuid::new_v4()`; not reproducible across bundles
4. **Directory hashing**: `fs::read_dir` iteration order affects hash order

### Bundle Format Details

- Header: 32 bytes (`MKPE` magic + version + sizes)
- Manifest: JSON, variable size
- Proofs: JSON, variable size
- Signature: Base64-encoded Ed25519
- Footer: 8 bytes (`EPKM` magic + CRC32)

### Hex Encoding

- SHA-256 hashes are lowercase hex (64 chars)
- Use `c.is_ascii_hexdigit()` for validation, not `c.is_ascii_lowercase()` (digits 0-9 fail)

### Path Handling

- Proof paths are relative to artifact root (no leading `/`)
- Use `/` separator regardless of OS (Unix convention)
- Bare filenames (no `/`) are valid for single-file cases

### Key Migration Testing

- `create_mkpe_bundle` requires a keypair; bundles are signed
- Verification with old key should fail after key migration
- Trusted key must be explicitly provided for verification to work