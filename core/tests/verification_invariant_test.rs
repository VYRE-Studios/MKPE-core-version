use morse_kirby_core::*;
use tempfile::TempDir;

#[test]
fn test_inner_signature_verification_enforcement() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let keypair = generate_keypair();
    let archive_path = temp_dir.path().join("test.mkpe");

    // 1. Create valid archive
    // We need some content
    let file_path = temp_dir.path().join("test.txt");
    std::fs::write(&file_path, "content")?;
    let archive = create_mkpe_bundle(temp_dir.path(), &keypair, &archive_path)?;

    // 2. Initial verify should pass
    let _verified = archive.verify()?; // Returns VerifiedMkpeArchive

    // We need to re-create the archive because verify() consumed it
    let mut archive = create_mkpe_bundle(temp_dir.path(), &keypair, &archive_path)?;

    // 3. Tamper with manifest field, INVALIDATING inner signature
    // We change a field that is NOT checked by the basic consistency logic,
    // but IS covered by the inner signature.
    let _old_version = archive.manifest.engine_version.clone();
    archive.manifest.engine_version = "hacked-version".to_string();

    // 4. Save tampered archive (re-signs outer)
    // This simulates wrapping a tampered manifest in a valid new bundle signature.
    archive.save(&archive_path, &keypair)?;

    // 5. Load tampered archive
    let loaded = MkpeArchive::load(&archive_path)?;

    // 6. Verify should FAIL because inner signature checks engine_version
    // If this passes, the bug is still present.
    match loaded.verify() {
        Ok(_) => panic!("Verification passed on tampered manifest! Inner signature check failed."),
        Err(_) => {} // Expected: verification should fail
    }

    Ok(())
}
