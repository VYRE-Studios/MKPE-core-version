use morse_kirby_core::generate_keypair;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::TempDir;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn mkpe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mkpe"))
}

fn write_keypair(temp_dir: &TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    let keypair = generate_keypair();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let key_dir = temp_dir.path().join(format!("keys_{}", n));
    std::fs::create_dir_all(&key_dir).unwrap();
    let private_key = key_dir.join("mkpe_private.key");
    let public_key = key_dir.join("mkpe_public.key");
    std::fs::write(&private_key, &keypair.private_key).unwrap();
    std::fs::write(&public_key, &keypair.public_key).unwrap();
    (private_key, public_key)
}

/// Derive deterministic key ID from public key (same algorithm as CLI)
fn key_id_from_pubkey(pubkey: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey.trim().as_bytes());
    hex::encode(&hasher.finalize()[..8])
}

#[test]
fn test_ownership_transfer_create_and_sign_json() {
    let temp_dir = TempDir::new().unwrap();
    let (alice_priv, _alice_pub) = write_keypair(&temp_dir);
    let (bob_priv, bob_pub) = write_keypair(&temp_dir);

    let transfer_json = temp_dir.path().join("transfer.json");

    // Alice creates the transfer manifest (seller signs first)
    let create = mkpe()
        .args([
            "--format",
            "json",
            "ownership",
            "transfer",
            "--asset",
            "char-42",
            "--previous",
            "genesis-0",
            "--from-key",
            alice_priv.to_str().unwrap(),
            "--to-key",
            bob_pub.to_str().unwrap(),
            "--nonce",
            "1",
            "--output",
            transfer_json.to_str().unwrap(),
            "--price",
            "10.5",
            "--currency",
            "ETH",
            "--royalty",
            "10",
            "--max-resales",
            "3",
        ])
        .output()
        .unwrap();

    assert!(
        create.status.success(),
        "create failed: stderr = {}",
        String::from_utf8_lossy(&create.stderr)
    );
    let created: serde_json::Value = serde_json::from_slice(&create.stdout).unwrap();
    assert_eq!(created["status"], "created");
    assert_eq!(created["executed"], false); // awaiting buyer signature
    assert!(transfer_json.exists());

    // Bob signs the transfer manifest
    let signed_json = temp_dir.path().join("transfer_signed.json");
    let sign = mkpe()
        .args([
            "--format",
            "json",
            "ownership",
            "sign",
            "--manifest",
            transfer_json.to_str().unwrap(),
            "--key",
            bob_priv.to_str().unwrap(),
            "--output",
            signed_json.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        sign.status.success(),
        "sign failed: stderr = {}",
        String::from_utf8_lossy(&sign.stderr)
    );
    let signed: serde_json::Value = serde_json::from_slice(&sign.stdout).unwrap();
    assert_eq!(signed["status"], "signed");
    assert_eq!(signed["executed"], true); // all required signatures present
}

#[test]
fn test_ownership_verify_chain_valid() {
    let temp_dir = TempDir::new().unwrap();
    let (alice_priv, alice_pub) = write_keypair(&temp_dir);
    let (bob_priv, bob_pub) = write_keypair(&temp_dir);
    let (carol_priv, carol_pub) = write_keypair(&temp_dir);

    let chain_dir = temp_dir.path().join("chain");
    std::fs::create_dir(&chain_dir).unwrap();

    let keys_dir = temp_dir.path().join("keys_dir");
    std::fs::create_dir(&keys_dir).unwrap();
    // Copy all public keys into keys_dir with unique names
    for (priv_path, pub_path) in [
        (&alice_priv, &alice_pub),
        (&bob_priv, &bob_pub),
        (&carol_priv, &carol_pub),
    ] {
        let parent = priv_path.parent().unwrap().file_name().unwrap().to_str().unwrap();
        let name = pub_path.file_name().unwrap().to_str().unwrap();
        std::fs::copy(pub_path, keys_dir.join(format!("{}_{}.pub", parent, name))).unwrap();
    }

    // Transfer 1: Alice -> Bob
    let t1 = chain_dir.join("t1.json");
    let create1 = mkpe()
        .args([
            "ownership",
            "transfer",
            "--asset",
            "char-42",
            "--previous",
            "genesis-0",
            "--from-key",
            alice_priv.to_str().unwrap(),
            "--to-key",
            bob_pub.to_str().unwrap(),
            "--nonce",
            "1",
            "--output",
            t1.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(create1.status.success(), "t1 create: {}", String::from_utf8_lossy(&create1.stderr));

    // Bob signs t1 (overwrites the unsigned manifest)
    let sign1 = mkpe()
        .args([
            "ownership",
            "sign",
            "--manifest",
            t1.to_str().unwrap(),
            "--key",
            bob_priv.to_str().unwrap(),
            "--output",
            t1.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(sign1.status.success(), "t1 sign: {}", String::from_utf8_lossy(&sign1.stderr));
    // Transfer 2: Bob -> Carol (previous is t1 transfer_id)
    let t1_manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&t1).unwrap()).unwrap();
    let t1_id = t1_manifest["transfer_id"].as_str().unwrap();

    let t2 = chain_dir.join("t2.json");
    let create2 = mkpe()
        .args([
            "ownership",
            "transfer",
            "--asset",
            "char-42",
            "--previous",
            t1_id,
            "--from-key",
            bob_priv.to_str().unwrap(),
            "--to-key",
            carol_pub.to_str().unwrap(),
            "--nonce",
            "2",
            "--output",
            t2.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(create2.status.success(), "t2 create: {}", String::from_utf8_lossy(&create2.stderr));

    // Carol signs t2
    // Carol signs t2 (overwrites the unsigned manifest)
    let sign2 = mkpe()
        .args([
            "ownership",
            "sign",
            "--manifest",
            t2.to_str().unwrap(),
            "--key",
            carol_priv.to_str().unwrap(),
            "--output",
            t2.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(sign2.status.success(), "t2 sign: {}", String::from_utf8_lossy(&sign2.stderr));
    // Verify the chain
    let verify = mkpe()
        .args([
            "--format",
            "json",
            "ownership",
            "verify-chain",
            "--asset",
            "char-42",
            "--genesis",
            "genesis-0",
            "--chain-dir",
            chain_dir.to_str().unwrap(),
            "--public-keys",
            keys_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        verify.status.success(),
        "verify failed with exit code: {:?}",
        verify.status.code()
    );
    let result: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(result["status"], "valid");
    assert_eq!(result["transfer_count"], 2);

    // Determine Carol's key_id for current owner assertion
    let carol_key_id = key_id_from_pubkey(&std::fs::read_to_string(&carol_pub).unwrap());
    assert_eq!(result["current_owner"], carol_key_id);
}

#[test]
fn test_ownership_revoke_breaks_chain() {
    let temp_dir = TempDir::new().unwrap();
    let (alice_priv, alice_pub) = write_keypair(&temp_dir);
    let (bob_priv, bob_pub) = write_keypair(&temp_dir);

    let chain_dir = temp_dir.path().join("chain");
    std::fs::create_dir(&chain_dir).unwrap();

    let keys_dir = temp_dir.path().join("keys_dir");
    std::fs::create_dir(&keys_dir).unwrap();
    for (_, pub_path) in [(&alice_priv, &alice_pub), (&bob_priv, &bob_pub)] {
        let name = pub_path.file_name().unwrap().to_str().unwrap();
        std::fs::copy(pub_path, keys_dir.join(format!("{name}.pub"))).unwrap();
    }

    // Create and fully sign transfer
    let t1 = chain_dir.join("t1.json");
    let create = mkpe()
        .args([
            "ownership",
            "transfer",
            "--asset",
            "char-42",
            "--previous",
            "genesis-0",
            "--from-key",
            alice_priv.to_str().unwrap(),
            "--to-key",
            bob_pub.to_str().unwrap(),
            "--nonce",
            "1",
            "--output",
            t1.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(create.status.success());

    let t1_signed = chain_dir.join("t1_signed.json");
    let sign = mkpe()
        .args([
            "ownership",
            "sign",
            "--manifest",
            t1.to_str().unwrap(),
            "--key",
            bob_priv.to_str().unwrap(),
            "--output",
            t1_signed.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(sign.status.success());

    let t1_manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&t1_signed).unwrap()).unwrap();
    let t1_id = t1_manifest["transfer_id"].as_str().unwrap();

    // Create revocation
    let revocation_json = temp_dir.path().join("revocation.json");
    let revoke = mkpe()
        .args([
            "--format",
            "json",
            "ownership",
            "revoke",
            "--transfer-id",
            t1_id,
            "--key",
            alice_priv.to_str().unwrap(),
            "--reason",
            "Account compromise",
            "--output",
            revocation_json.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        revoke.status.success(),
        "revoke failed: stderr = {}",
        String::from_utf8_lossy(&revoke.stderr)
    );
    let rev: serde_json::Value = serde_json::from_slice(&revoke.stdout).unwrap();
    assert_eq!(rev["status"], "revoked");
    assert!(revocation_json.exists());
}

#[test]
fn test_ownership_transfer_with_marketplace_json() {
    let temp_dir = TempDir::new().unwrap();
    let (alice_priv, _alice_pub) = write_keypair(&temp_dir);
    let (_bob_priv, bob_pub) = write_keypair(&temp_dir);
    let (_market_priv, market_pub) = write_keypair(&temp_dir);

    let transfer_json = temp_dir.path().join("transfer.json");

    let create = mkpe()
        .args([
            "--format",
            "json",
            "ownership",
            "transfer",
            "--asset",
            "char-99",
            "--previous",
            "genesis-0",
            "--from-key",
            alice_priv.to_str().unwrap(),
            "--to-key",
            bob_pub.to_str().unwrap(),
            "--marketplace-key",
            market_pub.to_str().unwrap(),
            "--nonce",
            "7",
            "--output",
            transfer_json.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        create.status.success(),
        "create with marketplace failed: stderr = {}",
        String::from_utf8_lossy(&create.stderr)
    );
    let created: serde_json::Value = serde_json::from_slice(&create.stdout).unwrap();
    assert_eq!(created["status"], "created");
    // Seller + marketplace signed; awaiting buyer
    assert_eq!(created["executed"], false);
}
