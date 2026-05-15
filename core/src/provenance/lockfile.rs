//! Parser for `Cargo.lock` -> `ResolvedDependency` list.
//!
//! Cargo.lock is the only authoritative source for the SHA-256 of each
//! crates.io dependency. `cargo metadata` knows what versions resolved
//! to what packages, but it does NOT carry the registry checksum -- that
//! lives only in the lockfile. Since SLSA L3 requires content digests for
//! the dependency closure, we parse the lockfile directly.
//!
//! Format reference: <https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html>
//!
//! ## What this module produces
//!
//! For each `[[package]]` entry in Cargo.lock we emit one
//! [`ResolvedDependency`] with:
//!
//! * `uri` -- a PURL-style identifier: `pkg:cargo/<name>@<version>` for
//!   registry deps, the raw `git+...#<rev>` URL for git deps.
//! * `digest.sha256` -- the lockfile `checksum` for registry deps.
//! * `name`, `version` -- copied from the lockfile.
//!
//! ## What this module deliberately skips
//!
//! * **Workspace path deps** (the MKPE crates themselves): they have neither
//!   `source` nor `checksum`. They are *the artifact being attested*, not
//!   dependencies of it. Including them as `resolvedDependencies` would be
//!   misleading.
//! * **Git deps without `checksum`** are returned in [`ParsedLockfile::git_deps_without_digest`]
//!   so the caller can decide how to handle them (warn, fetch+hash, fail).
//!   They are NOT silently included with a missing digest -- the schema
//!   requires `sha256`, and lying about a digest is worse than omitting one.
//!
//! ## Why not use the `cargo_lock` crate?
//!
//! `cargo_lock` would work, but it pulls in `cargo_metadata`, `semver`,
//! `url`, and a few more crates -- all of which would need `cargo-vet`
//! audit entries. `toml`@0.8 is already in our transitive tree (pulled in
//! by other workspace deps), so parsing the lockfile directly with `toml`
//! and `serde` is a strictly smaller supply-chain surface.

use crate::{
    provenance::{Digest, ResolvedDependency},
    MkpeError, Result,
};
use serde::Deserialize;
use std::path::Path;

// ---------------------------------------------------------------------------
// Raw lockfile shape (serde-only). Only the fields we need; unknown fields
// are ignored. `version` at the top level is left flexible because Cargo
// has shipped lockfile versions 1, 2, 3, and 4 with backward-compatible
// shapes for everything we care about.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawLockfile {
    #[serde(default)]
    package: Vec<RawPackage>,
}

#[derive(Debug, Deserialize)]
struct RawPackage {
    name: String,
    version: String,
    /// `registry+...`, `git+...?rev=...#<rev>`, or absent for workspace
    /// path dependencies.
    #[serde(default)]
    source: Option<String>,
    /// SHA-256 of the `.crate` tarball as published to the registry.
    /// Present only for registry sources.
    #[serde(default)]
    checksum: Option<String>,
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// Result of parsing a `Cargo.lock`.
///
/// `resolved` contains every dependency we can attest with a real digest.
/// `git_deps_without_digest` is intentionally split out so the caller never
/// silently mixes them in.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParsedLockfile {
    /// External dependencies that resolved to a registry and have a checksum.
    /// These are safe to include in `resolvedDependencies` as-is.
    pub resolved: Vec<ResolvedDependency>,

    /// Git-sourced dependencies. Excluded from `resolved` because the
    /// lockfile carries only the commit SHA (sha1), not a sha256 of the
    /// fetched source tree. The caller must hash these out-of-band (via
    /// `cargo fetch` + tree-hash) or accept the gap with explicit warnings.
    pub git_deps_without_digest: Vec<GitDep>,

    /// Workspace path members. Returned for visibility but never emitted
    /// as dependencies of the build -- they ARE the build.
    pub workspace_members: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GitDep {
    pub name: String,
    pub version: String,
    /// Raw `source` string from Cargo.lock, e.g.
    /// `git+https://github.com/foo/bar?rev=abc123#abc123`.
    pub source: String,
}

/// Parse a Cargo.lock file at `path` and classify every package.
///
/// This is a pure function: it does no network or filesystem access beyond
/// reading the lockfile itself. Tests can call it on a string literal via
/// [`parse_lockfile_str`].
pub fn parse_lockfile<P: AsRef<Path>>(path: P) -> Result<ParsedLockfile> {
    let text = std::fs::read_to_string(path.as_ref())?;
    parse_lockfile_str(&text)
}

/// Merge pre-computed SHA-256 digests for git-sourced packages into `parsed`.
///
/// `digests` maps the **exact** `source` string from `Cargo.lock` to a
/// lowercase 64-hex SHA-256 of the attested source tree. Every key must match
/// a row in [`ParsedLockfile::git_deps_without_digest`].
pub fn apply_git_dep_digests(
    parsed: &mut ParsedLockfile,
    digests: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    if digests.is_empty() {
        return Ok(());
    }

    for (src, digest_hex) in digests {
        if !is_lowercase_sha256(digest_hex) {
            return Err(MkpeError::ProvenanceError(format!(
                "git dep digest for {src:?} must be 64 lowercase hex chars; got {digest_hex:?}"
            )));
        }
        let pos = parsed
            .git_deps_without_digest
            .iter()
            .position(|g| g.source == *src)
            .ok_or_else(|| {
                MkpeError::ProvenanceError(format!(
                    "git_dep_digests entry references unknown or non-git source {src:?}; \
                     keys must match Cargo.lock [[package]].source exactly"
                ))
            })?;
        let git = parsed.git_deps_without_digest.remove(pos);
        parsed.resolved.push(ResolvedDependency {
            uri: format!("pkg:cargo/{}@{}", git.name, git.version),
            digest: Digest {
                sha256: digest_hex.clone(),
                ..Default::default()
            },
            name: Some(git.name),
            version: Some(git.version),
        });
    }

    parsed.resolved.sort_by(|a, b| a.uri.cmp(&b.uri));
    Ok(())
}

/// Same as [`parse_lockfile`] but takes the lockfile contents directly.
/// Used by tests and by callers that have already loaded the file.
pub fn parse_lockfile_str(text: &str) -> Result<ParsedLockfile> {
    let raw: RawLockfile = toml::from_str(text).map_err(|e| {
        MkpeError::ProvenanceError(format!("Cargo.lock parse failed: {e}"))
    })?;

    let mut out = ParsedLockfile::default();

    for pkg in raw.package {
        match classify(&pkg) {
            PkgKind::Workspace => {
                out.workspace_members.push((pkg.name, pkg.version));
            }
            PkgKind::Registry => {
                // Defensive: classify() only returns Registry when both
                // source and checksum are present, but assert it again so
                // an unwrap here would be a programmer error, not a panic.
                let checksum = pkg.checksum.expect("classify invariant: registry has checksum");
                if !is_lowercase_sha256(&checksum) {
                    return Err(MkpeError::ProvenanceError(format!(
                        "package {:?} version {:?} has non-sha256 checksum {:?}; \
                         lockfile may be corrupted or from an unsupported Cargo version",
                        pkg.name, pkg.version, checksum
                    )));
                }
                out.resolved.push(ResolvedDependency {
                    uri: format!("pkg:cargo/{}@{}", pkg.name, pkg.version),
                    digest: Digest {
                        sha256: checksum,
                        ..Default::default()
                    },
                    name: Some(pkg.name),
                    version: Some(pkg.version),
                });
            }
            PkgKind::Git => {
                out.git_deps_without_digest.push(GitDep {
                    name: pkg.name,
                    version: pkg.version,
                    source: pkg.source.unwrap_or_default(),
                });
            }
        }
    }

    // Deterministic order so two runs of the producer over the same
    // Cargo.lock emit byte-identical attestations.
    out.resolved.sort_by(|a, b| a.uri.cmp(&b.uri));
    out.git_deps_without_digest.sort_by(|a, b| a.name.cmp(&b.name));
    out.workspace_members.sort();

    Ok(out)
}

// ---------------------------------------------------------------------------
// Internal classification
// ---------------------------------------------------------------------------

enum PkgKind {
    /// Workspace path dep: no `source`, no `checksum`.
    Workspace,
    /// Registry dep with a published `.crate` checksum.
    Registry,
    /// Git dep: `source` starts with `git+`. Cargo.lock never records a
    /// content checksum for git sources.
    Git,
}

fn classify(pkg: &RawPackage) -> PkgKind {
    match (&pkg.source, &pkg.checksum) {
        (None, _) => PkgKind::Workspace,
        (Some(s), Some(_)) if s.starts_with("registry+") => PkgKind::Registry,
        (Some(s), _) if s.starts_with("git+") => PkgKind::Git,
        // Sparse-index registries also use `sparse+...`; treat as registry
        // when accompanied by a checksum.
        (Some(s), Some(_)) if s.starts_with("sparse+") => PkgKind::Registry,
        // Anything else (e.g. a registry source without a checksum, or an
        // unknown URL scheme) is suspicious. Bucket it as Git so the caller
        // sees it in the "no digest" pile rather than silently shipping
        // something we can't attest.
        _ => PkgKind::Git,
    }
}

fn is_lowercase_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but realistic lockfile covering all three package kinds.
    /// Embedded as a string literal so the test doesn't depend on filesystem
    /// layout.
    const SAMPLE: &str = r#"
version = 3

[[package]]
name = "mkpe_workspace_member"
version = "1.0.0-mkpe"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
dependencies = ["serde_derive"]

[[package]]
name = "sparse_indexed_dep"
version = "2.0.0"
source = "sparse+https://index.crates.io/"
checksum = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

[[package]]
name = "some_git_dep"
version = "0.5.0"
source = "git+https://github.com/example/repo?rev=abc123#abc123def456"
"#;

    #[test]
    fn classifies_all_three_package_kinds() {
        let parsed = parse_lockfile_str(SAMPLE).expect("parse");
        assert_eq!(parsed.workspace_members.len(), 1);
        assert_eq!(parsed.workspace_members[0].0, "mkpe_workspace_member");
        assert_eq!(parsed.resolved.len(), 2, "registry + sparse both count");
        assert_eq!(parsed.git_deps_without_digest.len(), 1);
        assert_eq!(parsed.git_deps_without_digest[0].name, "some_git_dep");
    }

    #[test]
    fn registry_deps_get_purl_uri_and_sha256() {
        let parsed = parse_lockfile_str(SAMPLE).expect("parse");
        let serde_dep = parsed
            .resolved
            .iter()
            .find(|d| d.name.as_deref() == Some("serde"))
            .expect("serde present");
        assert_eq!(serde_dep.uri, "pkg:cargo/serde@1.0.228");
        assert_eq!(
            serde_dep.digest.sha256,
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    }

    #[test]
    fn output_is_sorted_for_deterministic_attestations() {
        // Construct a lockfile where the natural input order differs from
        // sorted-by-uri order, then verify the parser sorts the output.
        let unordered = r#"
version = 3

[[package]]
name = "zzz"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"

[[package]]
name = "aaa"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2222222222222222222222222222222222222222222222222222222222222222"
"#;
        let parsed = parse_lockfile_str(unordered).expect("parse");
        let uris: Vec<&str> = parsed.resolved.iter().map(|d| d.uri.as_str()).collect();
        assert_eq!(
            uris,
            vec!["pkg:cargo/aaa@1.0.0", "pkg:cargo/zzz@1.0.0"],
            "resolved deps must be sorted by URI for byte-stable output"
        );
    }

    #[test]
    fn non_hex_checksum_is_rejected() {
        let bad = r#"
version = 3

[[package]]
name = "weird"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "not-a-hex-string-not-the-right-length-NOT-LOWERCASE-XXXXXXXXXXXXX"
"#;
        let err = parse_lockfile_str(bad).unwrap_err();
        assert!(
            format!("{err}").contains("non-sha256 checksum"),
            "expected sha256 validation error, got: {err}"
        );
    }

    #[test]
    fn apply_git_dep_digests_promotes_git_packages() {
        let mut parsed = parse_lockfile_str(SAMPLE).expect("parse");
        assert_eq!(parsed.git_deps_without_digest.len(), 1);
        let src = parsed.git_deps_without_digest[0].source.clone();
        let mut m = std::collections::BTreeMap::new();
        m.insert(
            src,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        );
        apply_git_dep_digests(&mut parsed, &m).expect("apply");
        assert!(parsed.git_deps_without_digest.is_empty());
        assert_eq!(parsed.resolved.len(), 3);
        let git = parsed
            .resolved
            .iter()
            .find(|d| d.name.as_deref() == Some("some_git_dep"))
            .expect("git dep in resolved");
        assert_eq!(
            git.digest.sha256,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn apply_git_dep_digests_rejects_unknown_source_key() {
        let mut parsed = parse_lockfile_str(SAMPLE).expect("parse");
        let mut m = std::collections::BTreeMap::new();
        m.insert(
            "git+https://github.com/nope/nope?rev=0#0".into(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        );
        let err = apply_git_dep_digests(&mut parsed, &m).expect_err("unknown key");
        assert!(
            format!("{err}").contains("unknown"),
            "unexpected err: {err}"
        );
    }

    #[test]
    fn empty_lockfile_returns_empty_parsed() {
        let parsed = parse_lockfile_str("version = 3").expect("parse");
        assert!(parsed.resolved.is_empty());
        assert!(parsed.git_deps_without_digest.is_empty());
        assert!(parsed.workspace_members.is_empty());
    }

    #[test]
    fn malformed_toml_surfaces_clear_error() {
        let err = parse_lockfile_str("not a valid toml :::").unwrap_err();
        assert!(
            format!("{err}").contains("Cargo.lock parse failed"),
            "expected parse-failed error, got: {err}"
        );
    }

    #[test]
    fn parses_our_own_real_cargo_lock() {
        // Integration check: the parser must handle MKPE's own real
        // Cargo.lock, not just minimal fixtures. This catches version-3
        // vs version-4 drift, dep entries we didn't expect, etc.
        let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("CARGO_MANIFEST_DIR has a parent")
            .to_path_buf();
        let lockfile_path = workspace_root.join("Cargo.lock");
        let parsed = parse_lockfile(&lockfile_path).unwrap_or_else(|e| {
            panic!("failed to parse real Cargo.lock at {lockfile_path:?}: {e}")
        });

        // Sanity bounds. The actual count fluctuates with dep updates, but
        // we should always have at least the MKPE workspace members and at
        // least a hundred registry deps.
        assert!(
            parsed.workspace_members.len() >= 6,
            "expected >=6 workspace members (core, cli, service, ui, ui_desktop, ui_tray), \
             got {}: {:?}",
            parsed.workspace_members.len(),
            parsed.workspace_members
        );
        assert!(
            parsed.resolved.len() > 100,
            "expected >100 resolved registry deps in our real tree, got {}",
            parsed.resolved.len()
        );

        // Every resolved dep must have a valid sha256 -- the producer
        // relies on this invariant.
        for dep in &parsed.resolved {
            assert_eq!(dep.digest.sha256.len(), 64, "dep {:?} digest wrong length", dep.uri);
            assert!(dep.uri.starts_with("pkg:cargo/"), "dep {:?} bad URI", dep.uri);
        }

        // morse_kirby_core must be in workspace_members, NOT in resolved.
        // If it appears in resolved we've accidentally promoted an internal
        // crate to an external dependency.
        let core_in_workspace = parsed
            .workspace_members
            .iter()
            .any(|(n, _)| n == "morse_kirby_core");
        let core_in_resolved = parsed
            .resolved
            .iter()
            .any(|d| d.name.as_deref() == Some("morse_kirby_core"));
        assert!(core_in_workspace, "morse_kirby_core must be a workspace member");
        assert!(!core_in_resolved, "morse_kirby_core must NOT be in resolvedDependencies");
    }
}
