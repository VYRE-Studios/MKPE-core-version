# MKPE

MKPE is a DNA tagging provenance engine for digital work.

It answers one critical question:

> Can we prove this artifact is authentic, unchanged, and traceable back to its source?

Creative assets, code bundles, AI outputs, schemas, builds, and project folders move through messy pipelines. Files get copied, modified, exported, re-uploaded, and passed between humans, agents, tools, and production systems. MKPE gives each protected artifact a cryptographic passport so trust can be verified before anything acts on it.

## What It Does

MKPE creates a sidecar `.mkpe` proof bundle for a file or folder. Every byte in the protected artifact contributes to SHA-256 content proofs. Those proofs are sealed into a signed manifest with system fingerprinting, timestamps, and Ed25519 signatures.

The first working loop is:

```text
Bundle it. Sign it. Verify it.
```

If the artifact changes, verification fails. If the signature is wrong, verification fails. If the proof bundle is corrupted, verification fails.

## Working Version

This version makes sidecar `.mkpe` bundles the source of truth. The original artifact is not modified. That keeps MKPE format-agnostic: it works for text, binaries, folders, release packages, schemas, assets, and generated outputs.

Embedded DNA tags are the next layer. The roadmap still includes steganographic embedding for media and custom binary tagging, but the authoritative proof starts with the sidecar bundle.

## CLI Quick Start

Generate a signing keypair:

```powershell
mkpe keygen --output .\keys
```

Create a DNA proof for a file or folder:

```powershell
mkpe dna create .\artifact-folder --key .\keys\mkpe_private.key --output .\artifact-folder.mkpe
```

If the sidecar is written inside the protected folder, it must use the reserved default name `.mkpe`; other in-folder output names are rejected so the proof file cannot appear as an unproven payload during verification.

Verify the current bytes against the sidecar proof and pin the expected signer:

```powershell
mkpe dna verify .\artifact-folder --bundle .\artifact-folder.mkpe --public-key .\keys\mkpe_public.key
```

For scripts and agents, use JSON output:

```powershell
mkpe --format json dna verify .\artifact-folder --bundle .\artifact-folder.mkpe --public-key .\keys\mkpe_public.key
```

Inspect a proof bundle:

```powershell
mkpe dna inspect .\artifact-folder.mkpe
```

Generate and verify a build attestation for the same artifact:

```powershell
mkpe attest generate .\artifact-folder --key .\keys\mkpe_private.key --bundle .\artifact-folder.mkpe --output .\build_attestation.json --attested-by ci --command "cargo build --release"
mkpe attest verify .\build_attestation.json --subject .\artifact-folder --bundle .\artifact-folder.mkpe --public-key .\keys\mkpe_public.key
```

Attestations are signed JSON documents that bind the subject hash, optional `.mkpe` bundle identity, build fingerprint, timestamp, command metadata, and signer identity.

The legacy commands remain available:

```powershell
mkpe bundle .\artifact-folder --key .\keys\mkpe_private.key --output .\artifact-folder.mkpe
mkpe verify .\artifact-folder.mkpe
mkpe inspect .\artifact-folder.mkpe
mkpe hash .\artifact.txt
mkpe validate-cdna .\schema.cdna.json
```

## Watched Folder Provenance

The Windows service can scan protected folders and enforce sidecar DNA proofs:

- New files receive sidecars when a service signing key is configured. File sidecars preserve the full filename, for example `report.txt.mkpe`.
- Existing sidecars are verified against current file bytes.
- Tampered files are written to the audit log as verification failures.
- Missing sidecars are rejected when auto-proving is disabled or no signing key is configured.

Default service key path:

```text
C:\ProgramData\MKPE\keys\mkpe_private.key
```

Expected public key sibling:

```text
C:\ProgramData\MKPE\keys\mkpe_public.key
```

Optional config values in `C:\ProgramData\MKPE\config.json`:

```json
{
  "service_config": {
    "watch_paths": ["C:\\Projects"],
    "interval_seconds": 900,
    "auto_create_missing_proofs": true
  },
  "signing": {
    "key_path": "C:\\ProgramData\\MKPE\\keys\\mkpe_private.key"
  },
  "logging": {
    "log_dir": "C:\\ProgramData\\MKPE\\logs"
  },
  "verification": {
    "skip_extensions": [".tmp", ".log", ".cache"]
  }
}
```

## Architecture

```text
Layer 1: Core Engine
  SHA-256 byte proofs, Ed25519 signatures, .mkpe archive format

Layer 2: Integration and Monitoring
  CLI workflows, watched-folder service, audit logs, policy enforcement

Layer 3: Build attestation + SLSA provenance
  Signed build metadata (`mkpe attest …`) and DSSE-wrapped SLSA Provenance v1.0 (`mkpe verify-attestation` / `mkpe build-attestation`)

Layer 4: Embedded DNA Tags
  Planned steganographic and format-specific embedded proof fingerprints
```

## Repository Layout

- `Cargo.toml` / `Cargo.lock` - Workspace root (six members; one lockfile for the whole graph).
- `rust-toolchain.toml` - Pinned Rust toolchain for reproducible builds.
- `deny.toml` / `supply-chain/` - `cargo-deny` and `cargo-vet` policy and audit ledger.
- `schemas/` - JSON Schema for SLSA provenance payloads (compile-time embedded in `core`).
- `.github/workflows/` - CI and release automation (see `release.yml` header for maturity).
- `core/` - Rust provenance engine, proof bundles, manifests, archive loading, artifact verification, SLSA `provenance` module.
- `cli/` - `mkpe` command-line interface.
- `service/` - Windows watched-folder integrity service.
- `ui/` - Shared UI primitives (Slint).
- `ui_desktop/` - Desktop protection dashboard.
- `ui_tray/` - System tray status app.
- `docs/` - Format, architecture, integration, **[release history](docs/RELEASES.md)**, and **[SLSA roadmap](docs/SLSA_PLAN.md)**.
- `attestation/` - Build attestation layer ✅ (implemented in `core/src/attestation.rs`)
- `stego/` - Planned embedded proof/steganography layer.

## Versioning and releases

- Crate versions use the `*-mkpe` suffix in each `Cargo.toml` (for example **`1.2.0-mkpe`** on `core` and `cli` today).
- **[GitHub Releases](https://github.com/VYRE-Studios/MKPE-core-version/releases)** — the latest **git tag** is currently **`v1.1.0`**. **`main`** includes newer work (SLSA pipeline, workspace layout, dependency bumps). See **[docs/RELEASES.md](docs/RELEASES.md)** for what is on `main` since that tag and how to cut **`v1.2.0`**.

## Build from source (workspace)

From the repository root:

```powershell
cargo build --workspace --locked
```

The workspace enables optional **TPM / YubiKey** features in `core` that may not compile on every host OS. For a minimal library check: `cargo check -p morse_kirby_core --no-default-features`. Release-style Windows binaries are built from Linux CI using **`cargo-xwin`** (see `docs/SLSA_PLAN.md` and `.github/workflows/release.yml`).

## SLSA build provenance (DSSE)

MKPE emits and verifies **SLSA Build Provenance v1.0** inside **DSSE** envelopes (in-toto v1), with schema validation from `schemas/provenance_v1.schema.json`. Roadmap and trust decisions: **`docs/SLSA_PLAN.md`**.

```powershell
mkpe verify-attestation --pubkey .\keys\mkpe_public.key --artifact .\mkpe.exe .\mkpe.exe.intoto.jsonl
mkpe build-attestation --artifact .\mkpe.exe --lockfile .\Cargo.lock --context .\build-context.json --key .\keys\mkpe_private.key --output .\mkpe.exe.intoto.jsonl
```

Pre-SLSA unsigned `build_attestation.json` files: `mkpe verify-attestation --legacy …` (exit **6**, informational only).

## Security disclosures

See **[SECURITY.md](SECURITY.md)** for how to report vulnerabilities.

## Security Model

MKPE proves integrity and provenance for bytes covered by a signed proof bundle. A self-contained bundle proves internal consistency; trusted authenticity requires binding verification to an expected public key with `--public-key` or an equivalent trust store. MKPE does not claim that an artifact is safe to execute, legally owned, or semantically correct.

Use sidecar `.mkpe` bundles as the authoritative proof. Use embedded tags later as a durability layer for assets that leave your control.
