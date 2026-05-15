# MKPE releases and versioning

This file is the **in-repo** companion to [GitHub Releases](https://github.com/VYRE-Studios/MKPE-core-version/releases). It tracks what shipped under which tag and what has landed on `main` since the last tag.

## Version scheme

- **Crates** (`core`, `cli`, etc.) use a `x.y.z-mkpe` version string in each `Cargo.toml` (for example `1.2.0-mkpe`). That is the **source-of-truth build identity** inside the workspace.
- **Git tags** (`v1.1.0`, …) track **public release points** on GitHub. They may trail the crate string briefly while a release is being prepared.

## Published GitHub releases

| Tag | Title (short) | Highlights |
|-----|----------------|--------------|
| [v1.1.0](https://github.com/VYRE-Studios/MKPE-core-version/releases/tag/v1.1.0) | MKPE v1.1.0 | Layer 3 build attestations (`mkpe attest …`), signed `build_attestation.json`, trusted public-key verification, JSON automation output. |
| [v1.0.2](https://github.com/VYRE-Studios/MKPE-core-version/releases/tag/v1.0.2) | MKPE v1.0.2 | Patch / stabilization (see release body on GitHub). |
| [v1.0.1](https://github.com/VYRE-Studios/MKPE-core-version/releases/tag/v1.0.1) | DNA trust hardening | DNA provenance trust improvements. |
| [v1.0.0](https://github.com/VYRE-Studios/MKPE-core-version/releases/tag/v1.0.0) | Working DNA provenance | Initial public DNA provenance loop. |

## On `main` since `v1.1.0` (not yet tagged as `v1.2.0`)

The following merged work is on **`main`** at the time this file was last updated. When you cut **`v1.2.0`**, use this list as the release-notes seed.

- **SLSA / supply chain (PR [#14](https://github.com/VYRE-Studios/MKPE-core-version/pull/14))**  
  - Workspace root `Cargo.toml` / single `Cargo.lock` for all six crates.  
  - SLSA Provenance v1.0 + in-toto Statement v1 + DSSE v1 pipeline in `core` (`provenance` module), JSON Schema in `schemas/`.  
  - CLI: `mkpe verify-attestation`, `mkpe build-attestation` (stable exit codes for CI).  
  - `cargo-deny` / `cargo-vet` scaffolding, `rust-toolchain.toml`, `SECURITY.md`, `docs/SLSA_PLAN.md`, `docs/security/KEY_ROTATION.md`.  
  - `.github/workflows/release.yml` — **manual** Phase 1.6+ scaffold (not yet Sigstore L3; see workflow header comments).

- **Genesis / policy / ownership / crypto (between tag and SLSA merge)**  
  Genesis certificate, policy engine v2, TPM/YubiKey paths, ownership in bundles, format-aware DNA, and related core hardening (see `git log v1.1.0..HEAD`).

- **Dependency bumps (Dependabot / maintenance)**  
  `rand` / `bytes` alignment across `cli`, `service`, `ui`, `ui_tray` (see merged PRs [#6](https://github.com/VYRE-Studios/MKPE-core-version/pull/6), [#12](https://github.com/VYRE-Studios/MKPE-core-version/pull/12), [#13](https://github.com/VYRE-Studios/MKPE-core-version/pull/13), [#15](https://github.com/VYRE-Studios/MKPE-core-version/pull/15), [#16](https://github.com/VYRE-Studios/MKPE-core-version/pull/16)).

### Suggested next tag

When you are ready to align the **Git tag** with the current **crate** line:

1. Confirm `main` is green for your release criteria (build, tests, `cargo deny` / `cargo vet` as you adopt them in CI).  
2. Tag `v1.2.0` at the chosen commit and create a GitHub Release with notes derived from this section + `docs/SLSA_PLAN.md` Phase summary.  
3. Run the **manual** `release` workflow for that ref if you need Windows cross-build artifacts and DSSE envelopes from CI.

## Release workflow (today)

- **GitHub Releases** — human-facing downloads and notes; see link above.  
- **`.github/workflows/release.yml`** — `workflow_dispatch` only; builds Windows MSVC artifacts on Ubuntu with `cargo-xwin` and emits attestations per workflow docs. **Not** auto-L3 until Phase 2.x trust chain is implemented (see `docs/SLSA_PLAN.md`).
