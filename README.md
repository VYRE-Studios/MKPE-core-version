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

Verify the current bytes against the sidecar proof:

```powershell
mkpe dna verify .\artifact-folder --bundle .\artifact-folder.mkpe
```

Inspect a proof bundle:

```powershell
mkpe dna inspect .\artifact-folder.mkpe
```

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

- New files receive `.mkpe` sidecars when a service signing key is configured.
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

Layer 3: Build Attestation
  Planned build environment and reproducibility proof

Layer 4: Embedded DNA Tags
  Planned steganographic and format-specific embedded proof fingerprints
```

## Repository Layout

- `core/` - Rust provenance engine, proof bundles, manifests, archive loading, artifact verification.
- `cli/` - `mkpe` command-line interface.
- `service/` - Windows watched-folder integrity service.
- `ui_desktop/` - Desktop protection dashboard.
- `ui_tray/` - System tray status app.
- `docs/` - Format, architecture, and integration documentation.
- `attestation/` - Planned build attestation layer.
- `stego/` - Planned embedded proof/steganography layer.

## Security Model

MKPE proves integrity and provenance for bytes covered by a signed proof bundle. It does not claim that an artifact is safe to execute, legally owned, or semantically correct. Trust still depends on key custody, policy enforcement, and downstream systems refusing failed verification results.

Use sidecar `.mkpe` bundles as the authoritative proof. Use embedded tags later as a durability layer for assets that leave your control.
