//! End-to-end CLI tests for `mkpe verify-attestation`.
//!
//! These tests build a real signed DSSE envelope using the public `core`
//! API, write it (and a paired pubkey/artifact) to a temp dir, then invoke
//! the compiled `mkpe` binary as a subprocess. We assert on:
//!
//!   * stable exit codes (the CI contract documented on `VerifyAttestation`)
//!   * the structure of `--json` output (the machine-readable contract)
//!   * human-friendly stderr on failure (so operators get clear signal)
//!
//! Anything you change about the exit-code map or the `--json` envelope
//! should break a test here on purpose.

use assert_cmd::Command;
use chrono::{DateTime, Utc};
use morse_kirby_core::{
    generate_keypair, CrossCompiler, ExternalParameters, InternalParameters, Metadata,
    ProvenanceBuilder, Runner, RustToolchain, Statement, WorkflowRef,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// Helper: construct a fully-valid Statement, sign it, and return the path
/// to the envelope file plus the signing keypair so the test can pass its
/// public key into the CLI.
struct Fixture {
    tmpdir: tempfile::TempDir,
    envelope_path: PathBuf,
    pubkey_path: PathBuf,
    pubkey_b64: String,
    artifact_path: PathBuf,
    artifact_sha256: String,
}

fn build_signed_fixture() -> Fixture {
    let tmpdir = tempfile::tempdir().expect("tempdir");

    // 1. Create an artifact on disk so the --artifact branch is testable.
    let artifact_path = tmpdir.path().join("mkpe-test.bin");
    let artifact_bytes = b"the contents that get attested";
    fs::write(&artifact_path, artifact_bytes).unwrap();
    let artifact_sha256 = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(artifact_bytes);
        hex::encode(h.finalize())
    };

    // 2. Build a Statement that names that artifact.
    let started: DateTime<Utc> = "2026-06-01T12:00:00Z".parse().unwrap();
    let finished: DateTime<Utc> = "2026-06-01T12:14:23Z".parse().unwrap();
    let statement = Statement::builder()
        .subject("mkpe-test.bin", &artifact_sha256)
        .external_parameters(ExternalParameters {
            source: "git+https://github.com/VyreVault/mkpe@1111111111111111111111111111111111111111".into(),
            ref_: "refs/tags/v1.1.0".into(),
            target: "x86_64-pc-windows-msvc".into(),
            profile: "dist".into(),
            workflow: WorkflowRef {
                path: ".github/workflows/release.yml".into(),
                ref_: "2".repeat(40),
            },
        })
        .internal_parameters(InternalParameters {
            rust_toolchain: RustToolchain {
                channel: "1.93.1".into(),
                host: "x86_64-unknown-linux-gnu".into(),
                rustc_commit: Some("3".repeat(40)),
            },
            runner: Runner {
                os: "ubuntu-24.04".into(),
                arch: "x86_64".into(),
                image: format!("ghcr.io/runners/ubuntu-24.04@sha256:{}", "4".repeat(64)),
            },
            cross_compiler: Some(CrossCompiler {
                tool: "cargo-xwin".into(),
                tool_version: "0.18.0".into(),
                msvc_sdk_sha256: "5".repeat(64),
                clang_version: "18.1.8".into(),
            }),
        })
        .resolved_dependencies(vec![])
        .builder_identity(ProvenanceBuilder {
            id: "https://github.com/VyreVault/mkpe/.github/workflows/release.yml@refs/tags/v1.1.0".into(),
            version: Some({
                let mut v = BTreeMap::new();
                v.insert("cargo".into(), "1.93.1".into());
                v
            }),
            builder_dependencies: vec![],
        })
        .metadata(Metadata {
            invocation_id: "https://github.com/VyreVault/mkpe/actions/runs/99999999".into(),
            started_on: started,
            finished_on: finished,
        })
        .build()
        .expect("fixture statement must build");

    // 3. Sign it.
    let keypair = generate_keypair();
    let envelope = statement.sign(&keypair).expect("sign");

    // 4. Persist envelope + pubkey to disk.
    let envelope_path = tmpdir.path().join("release.intoto.jsonl");
    fs::write(
        &envelope_path,
        serde_json::to_string_pretty(&envelope).unwrap(),
    )
    .unwrap();

    let pubkey_path = tmpdir.path().join("mkpe_public.key");
    fs::write(&pubkey_path, &keypair.public_key).unwrap();

    Fixture {
        tmpdir,
        envelope_path,
        pubkey_path,
        pubkey_b64: keypair.public_key,
        artifact_path,
        artifact_sha256,
    }
}

#[test]
fn happy_path_with_pubkey_literal_succeeds() {
    let f = build_signed_fixture();
    Command::cargo_bin("mkpe")
        .unwrap()
        .args([
            "verify-attestation",
            f.envelope_path.to_str().unwrap(),
            "--pubkey",
            &f.pubkey_b64,
        ])
        .assert()
        .success();
    drop(f.tmpdir);
}

#[test]
fn happy_path_with_pubkey_from_file_succeeds() {
    let f = build_signed_fixture();
    Command::cargo_bin("mkpe")
        .unwrap()
        .args([
            "verify-attestation",
            f.envelope_path.to_str().unwrap(),
            "--pubkey",
            f.pubkey_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    drop(f.tmpdir);
}

#[test]
fn json_mode_emits_machine_readable_success() {
    let f = build_signed_fixture();
    let out = Command::cargo_bin("mkpe")
        .unwrap()
        .args([
            "verify-attestation",
            f.envelope_path.to_str().unwrap(),
            "--pubkey",
            &f.pubkey_b64,
            "--json",
        ])
        .output()
        .expect("spawn");
    assert!(out.status.success(), "expected success, stderr={}", String::from_utf8_lossy(&out.stderr));

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .expect("--json output must be valid JSON");

    assert_eq!(parsed["ok"], true);
    assert!(parsed["builder_id"].as_str().unwrap().contains("VyreVault/mkpe"));
    assert!(parsed["subjects"].is_array());
    assert_eq!(parsed["subjects"][0]["sha256"], f.artifact_sha256);
    drop(f.tmpdir);
}

#[test]
fn artifact_match_succeeds_when_digest_matches() {
    let f = build_signed_fixture();
    Command::cargo_bin("mkpe")
        .unwrap()
        .args([
            "verify-attestation",
            f.envelope_path.to_str().unwrap(),
            "--pubkey",
            &f.pubkey_b64,
            "--artifact",
            f.artifact_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    drop(f.tmpdir);
}

#[test]
fn artifact_mismatch_exits_with_code_4() {
    let f = build_signed_fixture();

    // Write a DIFFERENT artifact at a different path, then ask the CLI to
    // verify *that* file against the attestation. The signature is still
    // valid, but the subject digest no longer matches.
    let other_path = f.tmpdir.path().join("not-the-real-artifact.bin");
    fs::write(&other_path, b"this is something else entirely").unwrap();

    Command::cargo_bin("mkpe")
        .unwrap()
        .args([
            "verify-attestation",
            f.envelope_path.to_str().unwrap(),
            "--pubkey",
            &f.pubkey_b64,
            "--artifact",
            other_path.to_str().unwrap(),
        ])
        .assert()
        .code(4);
    drop(f.tmpdir);
}

#[test]
fn wrong_pubkey_exits_with_code_2() {
    let f = build_signed_fixture();
    let other = generate_keypair();
    Command::cargo_bin("mkpe")
        .unwrap()
        .args([
            "verify-attestation",
            f.envelope_path.to_str().unwrap(),
            "--pubkey",
            &other.public_key,
        ])
        .assert()
        .code(2);
    drop(f.tmpdir);
}

#[test]
fn malformed_envelope_exits_with_code_5() {
    let f = build_signed_fixture();

    // Truncate the envelope file -> guaranteed JSON parse failure.
    let bad_path = f.tmpdir.path().join("broken.intoto.jsonl");
    fs::write(&bad_path, b"{not valid json").unwrap();

    Command::cargo_bin("mkpe")
        .unwrap()
        .args([
            "verify-attestation",
            bad_path.to_str().unwrap(),
            "--pubkey",
            &f.pubkey_b64,
        ])
        .assert()
        .code(5);
    drop(f.tmpdir);
}

#[test]
fn legacy_mode_exits_with_code_6_and_reports_claims() {
    // Build a tiny fixture that mimics the real-world `build_attestation.json`
    // shape: a placeholder signature, plus enough identifying fields that
    // --legacy can surface them.
    let tmp = tempfile::tempdir().unwrap();
    let legacy_path = tmp.path().join("build_attestation.json");
    let legacy_content = serde_json::json!({
        "schema_version": "1.0",
        "engine_version": "v1.0.0-mkpe",
        "engine_manifest_id": "test-manifest-id",
        "root_hash": "abc123def456",
        "timestamp_utc": "2025-10-08T15:45:00Z",
        "attested_by": "Test Suite",
        "signature": "To be generated with mkpe sign build_attestation.json"
    });
    fs::write(&legacy_path, serde_json::to_string_pretty(&legacy_content).unwrap()).unwrap();

    // Legacy mode must exit 6 even without --pubkey (legacy files aren't
    // verifiable by definition).
    let out = Command::cargo_bin("mkpe")
        .unwrap()
        .args([
            "verify-attestation",
            legacy_path.to_str().unwrap(),
            "--legacy",
            "--json",
        ])
        .output()
        .expect("spawn");

    assert_eq!(
        out.status.code().unwrap_or(-1),
        6,
        "legacy mode must always exit 6, even for well-formed files"
    );
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("--json output must be valid JSON");
    assert_eq!(report["ok"], false);
    assert_eq!(report["code"], "legacy_unsigned");
    assert_eq!(report["claims"]["engine_version"], "v1.0.0-mkpe");
    assert_eq!(report["claims"]["signature_present"], false,
        "placeholder signature must not be counted as present");
}

#[test]
fn missing_pubkey_in_non_legacy_mode_is_a_clear_error() {
    let f = build_signed_fixture();
    // No --pubkey, no --legacy: the CLI should refuse with a helpful
    // anyhow message, not a cryptic clap-level "missing argument" panic.
    let out = Command::cargo_bin("mkpe")
        .unwrap()
        .args(["verify-attestation", f.envelope_path.to_str().unwrap()])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "must fail without --pubkey");
    let stderr = String::from_utf8(out.stderr).unwrap_or_default();
    assert!(
        stderr.contains("--pubkey is required") && stderr.contains("--legacy"),
        "error must explain both --pubkey requirement and --legacy escape hatch, got: {stderr}"
    );
    drop(f.tmpdir);
}

#[test]
fn tampered_payload_exits_with_code_2_or_3() {
    let f = build_signed_fixture();

    // Load envelope, flip a byte in the base64 payload, write back.
    let env_text = fs::read_to_string(&f.envelope_path).unwrap();
    let mut env: serde_json::Value = serde_json::from_str(&env_text).unwrap();
    {
        let payload = env["payload"].as_str().unwrap().to_string();
        // Flip the last char from likely '=' or alphanum to something else.
        let mut chars: Vec<char> = payload.chars().collect();
        let len = chars.len();
        chars[len - 2] = if chars[len - 2] == 'A' { 'B' } else { 'A' };
        env["payload"] = serde_json::Value::String(chars.into_iter().collect());
    }
    fs::write(&f.envelope_path, serde_json::to_string(&env).unwrap()).unwrap();

    let out = Command::cargo_bin("mkpe")
        .unwrap()
        .args([
            "verify-attestation",
            f.envelope_path.to_str().unwrap(),
            "--pubkey",
            &f.pubkey_b64,
        ])
        .output()
        .expect("spawn");

    // Tamper detection can surface as either:
    //   2: signature didn't verify (most common -- the payload bytes changed)
    //   3: signature verified against PAE but the payload no longer schema-validates
    //   5: payload bytes happen to decode but JSON parse fails
    // All three are acceptable failure modes -- they all mean "rejected".
    let code = out.status.code().unwrap_or(-1);
    assert!(
        matches!(code, 2 | 3 | 5),
        "expected exit code 2, 3, or 5 for tampered payload; got {code}"
    );
    drop(f.tmpdir);
}
