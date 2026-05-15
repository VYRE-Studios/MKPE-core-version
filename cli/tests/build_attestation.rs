//! End-to-end test for `mkpe build-attestation`.
//!
//! This is the highest-value integration test in the repo: it exercises
//! the full producer pipeline (Cargo.lock parsing -> Statement assembly
//! -> DSSE signing -> file write) through the CLI surface CI will
//! actually invoke, then immediately turns around and verifies the
//! output through the matching `mkpe verify-attestation` path.
//!
//! If this test passes, the producer and verifier agree on the wire
//! format. If it fails, something has drifted -- usually the schema, the
//! sig algorithm, or one of the field-rename macros.

use assert_cmd::Command;
use std::fs;

/// Minimal Cargo.lock the producer can parse. Includes one workspace
/// member and one registry dep with a valid sha256 checksum.
const FIXTURE_LOCKFILE: &str = r#"
version = 3

[[package]]
name = "mkpe_test_local"
version = "0.0.0"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
"#;

/// Build a context.json that the CLI will deserialize into a
/// `BuildContextSpec`. Field names are snake_case (the spec's
/// JSON-native casing).
fn context_json() -> serde_json::Value {
    serde_json::json!({
        "source_uri": "git+https://github.com/VyreVault/mkpe@1111111111111111111111111111111111111111",
        "source_ref": "refs/tags/v1.1.0",
        "target": "x86_64-pc-windows-msvc",
        "profile": "dist",
        "workflow": {
            "path": ".github/workflows/release.yml",
            "ref": "2".repeat(40),
        },
        "rust_toolchain": {
            "channel": "1.93.1",
            "host": "x86_64-unknown-linux-gnu",
            "rustcCommit": "3".repeat(40),
        },
        "runner": {
            "os": "ubuntu-24.04",
            "arch": "x86_64",
            "image": format!("ghcr.io/runners/ubuntu-24.04@sha256:{}", "4".repeat(64)),
        },
        "cross_compiler": {
            "tool": "cargo-xwin",
            "toolVersion": "0.18.0",
            "msvcSdkSha256": "5".repeat(64),
            "clangVersion": "18.1.8",
        },
        "builder_id": "https://github.com/VyreVault/mkpe/.github/workflows/release.yml@refs/tags/v1.1.0",
        "builder_versions": {
            "cargo": "1.93.1",
        },
        "invocation_id": "https://github.com/VyreVault/mkpe/actions/runs/99999999",
        "started_on": "2026-06-01T12:00:00Z",
        "finished_on": "2026-06-01T12:14:23Z",
    })
}

#[test]
fn build_then_verify_round_trip() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // --- inputs ---
    let artifact = tmp.path().join("mkpe-release.bin");
    fs::write(&artifact, b"the actual release artifact bytes").unwrap();

    let lockfile = tmp.path().join("Cargo.lock");
    fs::write(&lockfile, FIXTURE_LOCKFILE).unwrap();

    let context = tmp.path().join("ctx.json");
    fs::write(
        &context,
        serde_json::to_string_pretty(&context_json()).unwrap(),
    )
    .unwrap();

    // --- generate signing keys via the same CLI subcommand a release
    //     workflow would use; we want to exercise the real key path,
    //     not a Rust-API shortcut. ---
    let key_dir = tmp.path().join("keys");
    fs::create_dir(&key_dir).unwrap();
    Command::cargo_bin("mkpe")
        .unwrap()
        .args(["keygen", "--output", key_dir.to_str().unwrap()])
        .assert()
        .success();
    let private_key_path = key_dir.join("mkpe_private.key");
    let public_key_path = key_dir.join("mkpe_public.key");
    assert!(private_key_path.exists() && public_key_path.exists());

    // --- produce the attestation ---
    let envelope_path = tmp.path().join("mkpe-release.intoto.jsonl");
    Command::cargo_bin("mkpe")
        .unwrap()
        .args([
            "build-attestation",
            "--artifact",
            artifact.to_str().unwrap(),
            "--lockfile",
            lockfile.to_str().unwrap(),
            "--context",
            context.to_str().unwrap(),
            "--key",
            private_key_path.to_str().unwrap(),
            "--output",
            envelope_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(envelope_path.exists(), "producer must write the envelope");

    // --- verify the attestation against the matching pubkey AND the
    //     original artifact in one CLI invocation (the way a CI consumer
    //     would chain them) ---
    let out = Command::cargo_bin("mkpe")
        .unwrap()
        .args([
            "verify-attestation",
            envelope_path.to_str().unwrap(),
            "--pubkey",
            public_key_path.to_str().unwrap(),
            "--artifact",
            artifact.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "round trip must verify; stderr={}, stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );

    let report: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(report["ok"], true);
    assert!(report["builder_id"]
        .as_str()
        .unwrap()
        .contains("VyreVault/mkpe"));
    let subjects = report["subjects"].as_array().expect("subjects array");
    assert_eq!(subjects.len(), 1);
    assert_eq!(subjects[0]["name"], "mkpe-release.bin");

    drop(tmp);
}

#[test]
fn build_attestation_fails_with_clear_error_on_unsupported_target() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let artifact = tmp.path().join("a.bin");
    fs::write(&artifact, b"x").unwrap();
    let lockfile = tmp.path().join("Cargo.lock");
    fs::write(&lockfile, FIXTURE_LOCKFILE).unwrap();

    // Mutate the context to use a target NOT in SUPPORTED_TARGETS. The
    // builder should reject this at .build() time, before any signing.
    let mut ctx = context_json();
    ctx["target"] = serde_json::Value::String("wasm32-unknown-unknown".into());
    let context = tmp.path().join("ctx.json");
    fs::write(&context, serde_json::to_string_pretty(&ctx).unwrap()).unwrap();

    let key_dir = tmp.path().join("keys");
    fs::create_dir(&key_dir).unwrap();
    Command::cargo_bin("mkpe")
        .unwrap()
        .args(["keygen", "--output", key_dir.to_str().unwrap()])
        .assert()
        .success();

    let envelope_path = tmp.path().join("out.intoto.jsonl");
    let out = Command::cargo_bin("mkpe")
        .unwrap()
        .args([
            "build-attestation",
            "--artifact",
            artifact.to_str().unwrap(),
            "--lockfile",
            lockfile.to_str().unwrap(),
            "--context",
            context.to_str().unwrap(),
            "--key",
            key_dir.join("mkpe_private.key").to_str().unwrap(),
            "--output",
            envelope_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn");

    assert!(!out.status.success(), "must fail for unsupported target");
    let stderr = String::from_utf8(out.stderr).unwrap_or_default();
    assert!(
        stderr.contains("unsupported target") || stderr.contains("wasm32"),
        "error message must name the rejected target, got: {stderr}"
    );
    assert!(!envelope_path.exists(), "must not write envelope on failure");
}
