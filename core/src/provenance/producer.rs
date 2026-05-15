//! High-level producer: build context -> signed DSSE envelope.
//!
//! This module is the integration point between MKPE's environment-aware
//! callers (the CLI, future CI scripts) and the pure type machinery in
//! [`super`]. It takes a [`BuildContext`] -- a struct of *already-resolved*
//! inputs from whichever runner is invoking us -- and emits a signed
//! [`DsseEnvelope`].
//!
//! ## Design choices
//!
//! * **No I/O beyond what's strictly needed.** The producer reads the
//!   artifact file (to hash it) and the Cargo.lock file (to enumerate
//!   deps). Everything else is data passed in. This keeps the producer
//!   testable from a `cargo test` harness without env-var games.
//! * **No clock calls inside `produce`.** The caller supplies
//!   `started_on` and `finished_on`. CI runners have these from the
//!   workflow context; local invocations supply `Utc::now()` at both ends
//!   of the build. This keeps `produce` a pure function, which is the only
//!   way the same inputs always produce the same output.
//! * **The artifact is hashed exactly once,** inside `produce`. We don't
//!   accept a pre-computed digest because that defeats the point -- the
//!   whole value proposition of an attestation is that the producer saw
//!   the artifact's bytes itself.

use crate::{
    provenance::{
        lockfile, BuildDefinition, Builder as ProvenanceBuilder, CrossCompiler, Digest,
        DsseEnvelope, ExternalParameters, InternalParameters, Metadata, ProvenanceSigner,
        RunDetails, Runner, RustToolchain, SlsaProvenance, Statement,
        Subject, WorkflowRef, BUILD_TYPE, PREDICATE_TYPE, STATEMENT_TYPE,
    },
    MkpeError, Result,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// BuildContext: every input the producer needs, in one struct.
// ---------------------------------------------------------------------------

/// Everything the producer needs to emit an attestation. Constructed by the
/// caller (CLI flags + env vars in CI, or test fixture in tests) and fed to
/// [`produce`] as a single value.
#[derive(Debug, Clone)]
pub struct BuildContext {
    /// Filesystem path to the artifact being attested. The file's bytes
    /// will be hashed; we never trust a caller-supplied digest.
    pub artifact_path: PathBuf,

    /// Subject name in the attestation. Conventionally the artifact's
    /// filename (e.g. `mkpe-1.1.0-x86_64-pc-windows-msvc.zip`).
    pub artifact_name: String,

    /// Filesystem path to the `Cargo.lock` for the build. We parse this
    /// for `resolvedDependencies`.
    pub cargo_lock_path: PathBuf,

    /// Canonical source URI, e.g.
    /// `git+https://github.com/VyreVault/mkpe@<commit-sha>`.
    pub source_uri: String,

    /// Git ref being built, e.g. `refs/tags/v1.1.0` or `refs/heads/main`.
    pub source_ref: String,

    /// Cargo target triple. Must be in
    /// [`crate::provenance::SUPPORTED_TARGETS`].
    pub target: String,

    /// Cargo profile (`dist` or `release`). Must be in
    /// [`crate::provenance::SUPPORTED_PROFILES`].
    pub profile: String,

    /// The release workflow's identity at the time of the build.
    pub workflow: WorkflowRef,

    pub rust_toolchain: RustToolchain,
    pub runner: Runner,

    /// Present when cross-compiling Windows artifacts from Linux via
    /// `cargo-xwin`. `None` for native builds.
    pub cross_compiler: Option<CrossCompiler>,

    /// Globally-unique builder identity URI. For a GitHub Actions run on
    /// our own runner, this is the workflow URI; for Sigstore-keyless
    /// (Phase 2) it will be the Fulcio cert identity.
    pub builder_id: String,

    /// Optional builder version map, surfaced as evidence of which tools
    /// produced the build.
    pub builder_versions: BTreeMap<String, String>,

    /// CI run identity, e.g.
    /// `https://github.com/VyreVault/mkpe/actions/runs/12345`.
    pub invocation_id: String,

    pub started_on: DateTime<Utc>,
    pub finished_on: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// BuildContextSpec: the JSON-deserializable subset
//
// The CLI takes paths (artifact, lockfile, output) as flags and everything
// else as a JSON context file. That keeps the CLI surface small while
// letting CI scripts compose a rich context from environment variables.
//
// Fields here mirror BuildContext minus the filesystem paths. We
// deliberately use snake_case in this JSON because it's an MKPE-internal
// format -- the on-wire SLSA-formatted attestation is built from it but
// is NOT shaped like it.
// ---------------------------------------------------------------------------

/// JSON-serializable subset of [`BuildContext`]. Read from a file by the
/// `mkpe build-attestation` CLI and merged with path arguments to form a
/// full `BuildContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildContextSpec {
    pub source_uri: String,
    pub source_ref: String,
    pub target: String,
    pub profile: String,
    pub workflow: WorkflowRef,
    pub rust_toolchain: RustToolchain,
    pub runner: Runner,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_compiler: Option<CrossCompiler>,
    pub builder_id: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub builder_versions: BTreeMap<String, String>,
    pub invocation_id: String,
    pub started_on: DateTime<Utc>,
    pub finished_on: DateTime<Utc>,
}

impl BuildContext {
    /// Assemble a full [`BuildContext`] from a JSON spec plus the
    /// filesystem paths the CLI captures separately.
    ///
    /// `artifact_name` defaults to the file name of `artifact_path`, but
    /// callers can override it explicitly for cases where the on-wire
    /// subject name should differ from the local filename (e.g. building
    /// from a temp dir).
    pub fn from_spec(
        spec: BuildContextSpec,
        artifact_path: PathBuf,
        cargo_lock_path: PathBuf,
        artifact_name: Option<String>,
    ) -> Result<Self> {
        let derived_name = artifact_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                MkpeError::ProvenanceError(
                    "artifact_path has no valid UTF-8 file name; supply --artifact-name".into(),
                )
            })?;
        Ok(Self {
            artifact_path,
            artifact_name: artifact_name.unwrap_or(derived_name),
            cargo_lock_path,
            source_uri: spec.source_uri,
            source_ref: spec.source_ref,
            target: spec.target,
            profile: spec.profile,
            workflow: spec.workflow,
            rust_toolchain: spec.rust_toolchain,
            runner: spec.runner,
            cross_compiler: spec.cross_compiler,
            builder_id: spec.builder_id,
            builder_versions: spec.builder_versions,
            invocation_id: spec.invocation_id,
            started_on: spec.started_on,
            finished_on: spec.finished_on,
        })
    }
}

// ---------------------------------------------------------------------------
// Output: envelope + visibility into what the producer skipped
// ---------------------------------------------------------------------------

/// Result of producing an attestation. The envelope is the deliverable;
/// the warnings expose anything the producer chose to omit so the caller
/// can surface them in human output.
#[derive(Debug, Clone)]
pub struct ProducedAttestation {
    pub envelope: DsseEnvelope,
    pub statement: Statement,
    /// Non-fatal: dependencies we couldn't attest with a sha256 digest
    /// (typically git deps without a published checksum). These are NOT
    /// included in the envelope. CI should treat a non-empty list as a
    /// signal to either fix the dep or accept the gap consciously.
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Producer entry point
// ---------------------------------------------------------------------------

/// Optional lockfile merge inputs for [`produce_with_options`].
#[derive(Debug, Clone, Default)]
pub struct ProduceOptions<'a> {
    /// Maps `Cargo.lock` `[[package]].source` (git URL) to a lowercase
    /// 64-hex SHA-256 of the checked-out source tree. See
    /// [`lockfile::apply_git_dep_digests`].
    pub git_dep_digests: Option<&'a BTreeMap<String, String>>,
}

/// Build and validate the in-toto Statement (artifact hash, lockfile closure)
/// without signing. Used for CI reproducibility checks and `--statement-only`.
pub fn prepare_attestation(
    ctx: &BuildContext,
    opts: ProduceOptions<'_>,
) -> Result<(Statement, Vec<String>)> {
    let artifact_sha256 = hash_file_sha256(&ctx.artifact_path)?;

    let mut parsed = lockfile::parse_lockfile(&ctx.cargo_lock_path)?;
    if let Some(map) = opts.git_dep_digests {
        lockfile::apply_git_dep_digests(&mut parsed, map)?;
    }

    let mut warnings = Vec::new();
    if !parsed.git_deps_without_digest.is_empty() {
        warnings.push(format!(
            "{} git dependency(ies) omitted from resolvedDependencies (no published checksum): {}",
            parsed.git_deps_without_digest.len(),
            parsed
                .git_deps_without_digest
                .iter()
                .map(|d| format!("{}@{}", d.name, d.version))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let statement = Statement::builder()
        .subject(&ctx.artifact_name, &artifact_sha256)
        .external_parameters(ExternalParameters {
            source: ctx.source_uri.clone(),
            ref_: ctx.source_ref.clone(),
            target: ctx.target.clone(),
            profile: ctx.profile.clone(),
            workflow: ctx.workflow.clone(),
        })
        .internal_parameters(InternalParameters {
            rust_toolchain: ctx.rust_toolchain.clone(),
            runner: ctx.runner.clone(),
            cross_compiler: ctx.cross_compiler.clone(),
        })
        .resolved_dependencies(parsed.resolved)
        .builder_identity(ProvenanceBuilder {
            id: ctx.builder_id.clone(),
            version: if ctx.builder_versions.is_empty() {
                None
            } else {
                Some(ctx.builder_versions.clone())
            },
            builder_dependencies: vec![],
        })
        .metadata(Metadata {
            invocation_id: ctx.invocation_id.clone(),
            started_on: ctx.started_on,
            finished_on: ctx.finished_on,
        })
        .build()?;

    Ok((statement, warnings))
}

/// Produce a signed DSSE envelope for the given build context.
///
/// The `signer` is any backend that implements [`ProvenanceSigner`]:
/// a `&KeyPair` for local-file ed25519 (Phase 1.6 default), an
/// `Ed25519LocalSigner` when call-site readability matters, or
/// [`super::CosignCliKeylessSigner`] for Sigstore keyless via the cosign CLI.
/// The producer is intentionally indifferent -- it only knows it gets
/// signed bytes back; the trust policy lives in the verifier.
///
/// Failure modes (each surfaces as a distinct error variant):
///
/// * `MkpeError::IoError` -- artifact or lockfile unreadable.
/// * `MkpeError::ProvenanceError` -- lockfile malformed, or invariant
///   violation caught by `StatementBuilder::build()`.
/// * `MkpeError::SchemaValidation` -- the assembled Statement doesn't
///   match the embedded JSON Schema. This is a producer bug -- the schema
///   and the Rust types should never disagree -- so we surface it as an
///   error rather than swallowing it.
/// * `MkpeError::CryptoError` -- the signing key is malformed or the
///   signer backend (Fulcio, KMS, ...) rejected the request.
pub fn produce_with_options<S: ProvenanceSigner + ?Sized>(
    ctx: &BuildContext,
    signer: &S,
    opts: ProduceOptions<'_>,
) -> Result<ProducedAttestation> {
    let (statement, warnings) = prepare_attestation(ctx, opts)?;
    let envelope = statement.sign(signer)?;
    Ok(ProducedAttestation {
        envelope,
        statement,
        warnings,
    })
}

/// Same as [`produce_with_options`] with default options (no git tree digests).
pub fn produce<S: ProvenanceSigner + ?Sized>(
    ctx: &BuildContext,
    signer: &S,
) -> Result<ProducedAttestation> {
    produce_with_options(ctx, signer, ProduceOptions::default())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// SHA-256 a file in fixed-size chunks. Streams instead of loading into
/// memory so the producer handles release artifacts of any size.
fn hash_file_sha256(path: &Path) -> Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(MkpeError::IoError)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(MkpeError::IoError)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

// Suppress dead-code warnings for re-exports we declare for the public API
// but don't use inside this file directly.
#[allow(dead_code)]
const _USE_PUBLIC_CONSTS: (&str, &str, &str) = (STATEMENT_TYPE, PREDICATE_TYPE, BUILD_TYPE);
#[allow(dead_code)]
const _USE_HELPER_TYPES: fn(SlsaProvenance, BuildDefinition, RunDetails, Subject, Digest) = |_, _, _, _, _| {};

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;

    /// Minimal Cargo.lock fixture so tests don't depend on the workspace
    /// lockfile's contents.
    const FIXTURE_LOCKFILE: &str = r#"
version = 3

[[package]]
name = "mkpe_local"
version = "0.0.0"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
"#;

    fn fixture_ctx(tmp: &tempfile::TempDir) -> BuildContext {
        let artifact = tmp.path().join("mkpe-test.bin");
        std::fs::write(&artifact, b"attested-content").unwrap();

        let lockfile = tmp.path().join("Cargo.lock");
        std::fs::write(&lockfile, FIXTURE_LOCKFILE).unwrap();

        BuildContext {
            artifact_path: artifact,
            artifact_name: "mkpe-test.bin".into(),
            cargo_lock_path: lockfile,
            source_uri: "git+https://github.com/VyreVault/mkpe@1111111111111111111111111111111111111111".into(),
            source_ref: "refs/tags/v1.1.0".into(),
            target: "x86_64-pc-windows-msvc".into(),
            profile: "dist".into(),
            workflow: WorkflowRef {
                path: ".github/workflows/release.yml".into(),
                ref_: "2".repeat(40),
            },
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
            builder_id: "https://github.com/VyreVault/mkpe/.github/workflows/release.yml@refs/tags/v1.1.0".into(),
            builder_versions: {
                let mut m = BTreeMap::new();
                m.insert("cargo".into(), "1.93.1".into());
                m
            },
            invocation_id: "https://github.com/VyreVault/mkpe/actions/runs/99999999".into(),
            started_on: "2026-06-01T12:00:00Z".parse().unwrap(),
            finished_on: "2026-06-01T12:14:23Z".parse().unwrap(),
        }
    }

    #[test]
    fn produce_emits_envelope_that_self_verifies() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(&tmp);
        let key = generate_keypair();

        let result = produce(&ctx, &key).expect("produce");

        // Sanity: subject digest is the actual SHA-256 of the artifact bytes.
        let expected = {
            let mut h = Sha256::new();
            h.update(b"attested-content");
            hex::encode(h.finalize())
        };
        assert_eq!(result.statement.subject[0].digest.sha256, expected);

        // Envelope must verify against the signing key.
        let verified = result
            .envelope
            .verify(&key.public_key)
            .expect("self-verify");
        assert_eq!(result.statement, verified);
    }

    #[test]
    fn produce_is_deterministic_for_same_inputs() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(&tmp);
        let key = generate_keypair();

        let a = produce(&ctx, &key).expect("produce a");
        let b = produce(&ctx, &key).expect("produce b");

        // The Statement bytes must be byte-identical -- this is the
        // foundation of reproducible attestations. (Signatures CAN differ
        // because ed25519 signatures over the same data are deterministic
        // per RFC 8032, but a future signer swap to ECDSA would not be;
        // we only assert determinism of the statement here.)
        assert_eq!(
            a.statement.to_canonical_json().unwrap(),
            b.statement.to_canonical_json().unwrap(),
            "the same BuildContext must produce byte-identical statements"
        );
    }

    #[test]
    fn produce_surfaces_warning_for_git_deps() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = fixture_ctx(&tmp);

        // Overwrite the lockfile with one that has a git dep.
        std::fs::write(
            &ctx.cargo_lock_path,
            r#"
version = 3

[[package]]
name = "mkpe_local"
version = "0.0.0"

[[package]]
name = "some_fork"
version = "0.1.0"
source = "git+https://github.com/example/fork?rev=abc#abc"
"#,
        )
        .unwrap();
        // Avoid the "empty resolvedDependencies" edge case by leaving
        // ctx alone otherwise.
        ctx.artifact_path = ctx.artifact_path.clone();

        let key = generate_keypair();
        let result = produce(&ctx, &key).expect("produce");

        assert!(
            result.warnings.iter().any(|w| w.contains("some_fork")),
            "expected git-dep warning, got: {:?}",
            result.warnings
        );
        assert_eq!(
            result.statement.predicate.build_definition.resolved_dependencies.len(),
            0,
            "git deps must NOT be included in resolvedDependencies"
        );
    }

    #[test]
    fn produce_with_git_digest_includes_git_in_resolved() {
        let tmp = tempfile::tempdir().unwrap();
        let artifact = tmp.path().join("mkpe-test.bin");
        std::fs::write(&artifact, b"attested-content").unwrap();

        let lockfile = tmp.path().join("Cargo.lock");
        std::fs::write(
            &lockfile,
            r#"
version = 3

[[package]]
name = "mkpe_local"
version = "0.0.0"

[[package]]
name = "some_fork"
version = "0.1.0"
source = "git+https://github.com/example/fork?rev=abc#abc"
"#,
        )
        .unwrap();

        let started: chrono::DateTime<chrono::Utc> = "2026-06-01T12:00:00Z".parse().unwrap();
        let finished: chrono::DateTime<chrono::Utc> = "2026-06-01T12:14:23Z".parse().unwrap();
        let ctx = BuildContext {
            artifact_path: artifact,
            artifact_name: "mkpe-test.bin".into(),
            cargo_lock_path: lockfile,
            source_uri: "git+https://github.com/VyreVault/mkpe@1111111111111111111111111111111111111111".into(),
            source_ref: "refs/tags/v1.1.0".into(),
            target: "x86_64-pc-windows-msvc".into(),
            profile: "dist".into(),
            workflow: WorkflowRef {
                path: ".github/workflows/release.yml".into(),
                ref_: "2".repeat(40),
            },
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
            builder_id: "https://github.com/VyreVault/mkpe/.github/workflows/release.yml@refs/tags/v1.1.0".into(),
            builder_versions: BTreeMap::new(),
            invocation_id: "https://github.com/VyreVault/mkpe/actions/runs/99999999".into(),
            started_on: started,
            finished_on: finished,
        };

        let mut m = BTreeMap::new();
        m.insert(
            "git+https://github.com/example/fork?rev=abc#abc".into(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        );
        let opts = ProduceOptions {
            git_dep_digests: Some(&m),
        };
        let key = generate_keypair();
        let result = produce_with_options(&ctx, &key, opts).expect("produce");

        assert!(
            !result.warnings.iter().any(|w| w.contains("some_fork")),
            "git dep should not be warned when digest supplied: {:?}",
            result.warnings
        );
        let names: Vec<_> = result
            .statement
            .predicate
            .build_definition
            .resolved_dependencies
            .iter()
            .filter_map(|d| d.name.as_deref())
            .collect();
        assert!(names.contains(&"some_fork"));
    }

    #[test]
    fn missing_artifact_file_returns_io_error() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = fixture_ctx(&tmp);
        ctx.artifact_path = tmp.path().join("does-not-exist.bin");
        let key = generate_keypair();
        let err = produce(&ctx, &key).expect_err("must fail");
        assert!(matches!(err, MkpeError::IoError(_)));
    }

    #[test]
    fn time_order_violation_is_rejected_by_builder() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = fixture_ctx(&tmp);
        ctx.finished_on = "2025-01-01T00:00:00Z".parse().unwrap();
        ctx.started_on = "2026-01-01T00:00:00Z".parse().unwrap();
        let key = generate_keypair();
        let err = produce(&ctx, &key).expect_err("must fail");
        assert!(
            matches!(err, MkpeError::ProvenanceError(_)),
            "expected ProvenanceError, got: {err:?}"
        );
    }
}
