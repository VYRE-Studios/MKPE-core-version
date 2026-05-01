use morse_kirby_core::*;
use tempfile::TempDir;

#[test]
fn test_inner_signature_verification_enforcement() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let artifact_dir = temp_dir.path().join("artifact");
    std::fs::create_dir(&artifact_dir)?;
    let archive_path = temp_dir.path().join("test.mkpe");

    // 1. Create valid archive with some content
    let file_path = artifact_dir.join("test.txt");
    std::fs::write(&file_path, "content")?;
    let archive = create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;

    // 2. Initial verify should pass
    let _verified = archive.verify()?; // Returns VerifiedMkpeArchive

    // We need to re-create the archive because verify() consumed it
    let mut archive = create_mkpe_bundle(&artifact_dir, &keypair, &archive_path)?;

    // 3. Tamper with manifest field, INVALIDATING inner signature
    let _old_version = archive.manifest.engine_version.clone();
    archive.manifest.engine_version = "hacked-version".to_string();

    // 4. Save tampered archive (re-signs outer)
    archive.save(&archive_path, &keypair)?;

    // 5. Load tampered archive
    let loaded = MkpeArchive::load(&archive_path)?;

    // 6. Verify should FAIL because inner signature checks engine_version
    match loaded.verify() {
        Ok(_) => panic!("Verification passed on tampered manifest! Inner signature check failed."),
        Err(_) => {} // Expected: verification should fail
    }

    Ok(())
}
