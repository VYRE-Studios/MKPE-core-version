# MKPE releases and versioning

This file is the **in-repo** companion to [GitHub Releases](https://github.com/VYRE-Studios/MKPE-core-version/releases). It tracks what shipped under which tag.

## Version scheme

- **Crates** (`core`, `cli`, etc.) use a `x.y.z-mkpe` version string in each `Cargo.toml`. **`v1.2.0`** aligns with **`1.2.0-mkpe`** on `core` and `cli`.
- **Git tags** (`v1.2.0`, …) are **public release points** on GitHub. Comparing **`v1.1.0...v1.2.0`** shows only what changed between those two releases (not the whole history back to the repository’s first commit).

## Published GitHub releases

| Tag | Title (short) | Highlights |
|-----|----------------|--------------|
| [v1.2.0](https://github.com/VYRE-Studios/MKPE-core-version/releases/tag/v1.2.0) | MKPE v1.2.0 | Workspace + SLSA provenance **format & tooling** (through Phase **2.1**): DSSE / in-toto / SLSA v1 schema, `verify-attestation` / `build-attestation`, `cargo deny` / `cargo vet`, manual `release.yml` scaffold. **Not** full SLSA **Build L3** trust chain yet (see below). Also: genesis, policy v2, TPM/YubiKey, ownership-in-bundle, DNA hardening, Dependabot bumps. |
| [v1.1.0](https://github.com/VYRE-Studios/MKPE-core-version/releases/tag/v1.1.0) | MKPE v1.1.0 | Layer 3 build attestations (`mkpe attest …`), signed `build_attestation.json`, trusted public-key verification, JSON automation output. |
| [v1.0.2](https://github.com/VYRE-Studios/MKPE-core-version/releases/tag/v1.0.2) | MKPE v1.0.2 | Patch / stabilization (see release body on GitHub). |
| [v1.0.1](https://github.com/VYRE-Studios/MKPE-core-version/releases/tag/v1.0.1) | DNA trust hardening | DNA provenance trust improvements. |
| [v1.0.0](https://github.com/VYRE-Studios/MKPE-core-version/releases/tag/v1.0.0) | Working DNA provenance | Initial public DNA provenance loop. |

## SLSA Build Level 3 — what v1.2.0 includes vs. what is still planned

**Included in v1.2.0 (Phases through ~2.1 on the internal roadmap — see `docs/SLSA_PLAN.md`):**

- Single **Cargo workspace** (root `Cargo.toml` / one `Cargo.lock` for six crates).
- **SLSA Provenance v1.0** + **in-toto Statement v1** + **DSSE v1** types, canonical JSON, **JSON Schema** validation (`schemas/provenance_v1.schema.json`).
- **Producer** (`mkpe build-attestation`) and **verifier** (`mkpe verify-attestation`) with **stable CI exit codes**; `--legacy` for old unsigned JSON.
- **`ProvenanceSigner`** trait (Ed25519 today; hook for Sigstore later).
- **`cargo-deny`** / **`cargo-vet`** scaffolding, **`rust-toolchain.toml`**, **`SECURITY.md`**, key-rotation doc.
- **`.github/workflows/release.yml`** — **manual** `workflow_dispatch`; cross-build + ephemeral Ed25519 attestation in CI per workflow comments — **explicitly not** claimed as SLSA L3–grade trust yet.

**Not yet shipped** (later phases; required for a defensible **SLSA Build L3** claim end-to-end):

- **Sigstore Keyless** (OIDC → Fulcio → ephemeral signing; Rekor upload).
- **`slsa-verifier`** (or equivalent) as a **release gate** on emitted artifacts.
- **Runner / environment pinning** to digests, **two-runner reproducibility** checks, and other CI hardening called out in `docs/SLSA_PLAN.md` Phase 2.2+.

So: **v1.2.0** ships the **formats, libraries, and CLI** on the path to L3; it does **not** by itself mean every published binary is already attested under a **full L3 builder identity**.

## Release workflow (today)

- **GitHub Releases** — human-facing notes and optional binaries you attach.  
- **`.github/workflows/release.yml`** — `workflow_dispatch` only; see the workflow header for maturity. Run it against **`refs/tags/v1.2.0`** when you want CI-built Windows artifacts + envelopes for this tag.

## Why GitHub might still show a huge “initial” history

The repository’s **first commit** (`Initial commit for MKPE release`) imported a large tree. That is **unchanged** by tagging. What **does** bound review scope for a release is the **compare range**:  
`https://github.com/VYRE-Studios/MKPE-core-version/compare/v1.1.0...v1.2.0` — that diff is only the work **after** `v1.1.0`.
