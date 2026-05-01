# MKPE Architecture – Layer Stack

**Version**: 1.0.0-mkpe  
**Status**: Core layer complete, additional layers defined  
**Date**: October 8, 2025

---

## Overview

MKPE uses a **layered architecture** where each layer adds functionality without modifying the core provenance engine. This keeps the canonical freeze pure while allowing extensibility.

---

## Layer Stack

```
┌─────────────────────────────────────────────────┐
│         Application / Integrator                 │
│    (Kalyx, Axon, Creative OS, etc.)             │
└─────────────────────────────────────────────────┘
                     ↓ uses
┌─────────────────────────────────────────────────┐
│   Layer 4: Steganography (optional)             │
│   Embeds proof into media files                 │
│   Location: C:\mkpe\stego\                      │
│   Status: DEFINED, not implemented              │
└─────────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────┐
│   Layer 3: Attestation (optional)               │
│   Build environment verification                 │
│   Location: C:\mkpe\attestation\                │
│   Status: DEFINED, not implemented              │
└─────────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────┐
│   Layer 2: Monitoring & Integration             │
│   Integrity checks, audit logs, policy          │
│   Location: C:\Kalyx\MKPE\tools\                │
│   Status: ✅ COMPLETE                           │
└─────────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────┐
│   Layer 1: Core MKPE Engine (FROZEN)            │
│   Ed25519, SHA-256, .mkpe format                │
│   Location: C:\mkpe\                            │
│   Status: 🔒 FROZEN v1.0.0                      │
└─────────────────────────────────────────────────┘
```

---

## Layer 1: Core MKPE Engine 🔒 FROZEN

### Responsibility
- Ed25519 digital signatures
- SHA-256 content hashing
- `.mkpe` binary format (header, manifest, proofs, signature, footer)
- Proof generation and verification
- C-DNA schema support

### Files
```
C:\mkpe\
├── cli\target\release\mkpe.exe
├── core\target\release\morse_kirby_core.lib
├── core\src\*.rs
└── mkpe_core_v1.0.0.mkpe (self-signed)
```

### Interface
- **CLI**: `mkpe.exe {keygen|bundle|sign|verify|inspect|hash|validate-cdna|version}`
- **API**: `morse_kirby_core` Rust crate
- **Format**: `.mkpe` binary bundles

### Status
✅ **COMPLETE and FROZEN** – v1.0.0 canonical freeze  
**Never modify** – create new versions with migration path

---

## Layer 2: Monitoring & Integration ✅ COMPLETE

### Responsibility
- Daily integrity monitoring
- Audit log management
- Integration policy enforcement
- Startup verification
- Error handling and logging

### Files
```
C:\Kalyx\MKPE\
├── tools\Monitor-MKPEIntegrity.ps1
├── audit\
│   ├── integrity.log
│   ├── operations.log
│   └── rejections.log
└── C:\mkpe\
    ├── docs\README_USAGE.md
    ├── docs\mkpe_integration.json
    └── tools\Invoke-MKPE.ps1
```

### Interface
- **PowerShell**: `Monitor-MKPEIntegrity.ps1`, `Invoke-MKPE.ps1`
- **Policy**: `mkpe_integration.json` (machine-readable)
- **Logs**: JSON-formatted audit entries

### Status
✅ **COMPLETE** – Ready for deployment  
Scheduled task runs daily at 9 AM

---

## Layer 3: Attestation (Future)

### Responsibility
- Record build environment metadata
- Verify compiler, dependencies, system info
- Sign attestation separately from bundle
- Enable build reproducibility verification

### Proposed Files
```
C:\mkpe\attestation\
├── build_attestation.json (schema)
├── mkpe_attest.exe (CLI, future)
├── lib_attestation.rs (API, future)
└── docs\
    └── attestation_usage.md
```

### Proposed Schema

```json
{
  "schema_version": "1.0",
  "engine_manifest_id": "6260a764-7901-4997-9a85-898d728e760d",
  "engine_version": "v1.0.0-mkpe",
  "root_hash": "9b5041f701ba5279",
  "build_fingerprint": {
    "os": "Windows 10.0.26100",
    "rustc_version": "1.81.0-stable",
    "target_triple": "x86_64-pc-windows-msvc",
    "compiler_flags": "--release",
    "dependencies_hash": "sha256:...",
    "cpu": "AMD Ryzen 9 5900X",
    "memory_gb": 64
  },
  "timestamp_utc": "2025-10-08T15:00:00Z",
  "attested_by": "build_system_id",
  "signature": "<ed25519_signature>"
}
```

### Proposed Workflow

```bash
# During build
1. Compile MKPE core
2. mkpe_attest.exe generate --output build_attestation.json
3. mkpe.exe sign build_attestation.json -k engine.key
4. Include attestation in bundle metadata
```

### Verification

```bash
# On deployment
mkpe_attest.exe verify build_attestation.json --pubkey engine_public.key
```

### Status
📋 **DEFINED** – Schema ready, implementation pending  
**Next Step**: Implement `mkpe_attest` CLI tool

---

## Layer 4: Steganography (Future)

### Responsibility
- Embed proof fingerprints into media files
- Extract and verify embedded proofs
- Support common media formats (images, audio, video, binaries)
- Non-destructive, reversible embedding

### Proposed Files
```
C:\mkpe\stego\
├── mkpe_stego.exe (CLI, future)
├── libmkpe_stego.dll (API, future)
├── schemas\
│   └── stego_manifest_v1.json
└── docs\
    └── stego_usage.md
```

### Proposed Workflow

```bash
# Embed proof into asset
mkpe_stego.exe embed image.png \
  --from-bundle project.mkpe \
  --output image_provenanced.png

# Extract and verify
mkpe_stego.exe extract image_provenanced.png \
  --verify project.mkpe
```

### Supported Formats (Planned)

| Format | Method | Status |
|--------|--------|--------|
| PNG | LSB or metadata chunk | Planned |
| JPEG | EXIF or comment segment | Planned |
| MP3 | ID3v2 tags | Planned |
| MP4 | User data atom | Planned |
| Binary | Custom segment | Planned |

### Design Principles

1. **Never modify `.mkpe`** – Read root hash, embed separately
2. **Reversible** – Original asset recoverable
3. **Non-destructive** – Quality preserved
4. **Verifiable** – Extracted hash matches bundle

### Status
📋 **DEFINED** – Architecture ready, implementation pending  
**Next Step**: Design LSB embedding for PNG

---

## Integration Points

### How Layers Connect

```
Application
    ↓ exports artifact
Layer 4 (Stego) - embeds hash into media
    ↓ reads root_hash from
Layer 3 (Attestation) - signs build environment
    ↓ included in
Layer 2 (Integration) - enforces policy
    ↓ calls
Layer 1 (Core) - creates .mkpe bundle
    ↓ produces
.mkpe file (signed, verified, proven)
```

### Data Flow

```
1. Build artifact → Layer 1 (Core)
   └→ Creates .mkpe bundle
   
2. Bundle + build info → Layer 3 (Attestation)
   └→ Creates signed attestation.json
   
3. Attestation + bundle → Layer 2 (Integration)
   └→ Enforces policy, logs operation
   
4. Original asset + bundle → Layer 4 (Stego)
   └→ Embeds proof in media
   
5. Final artifact = Asset with embedded proof + .mkpe bundle + attestation
```

---

## File Locations

### Current Structure

```
C:\mkpe\                          # Core engine (frozen)
├── cli\
├── core\
├── docs\
│   ├── README_USAGE.md           ✅
│   ├── mkpe_integration.json     ✅
│   ├── format_spec_v1.0.md       ✅
│   └── ARCHITECTURE_LAYERS.md    ✅ (this file)
├── tools\
├── examples\
├── validation\
├── attestation\                  📋 (placeholder)
└── stego\                        📋 (placeholder)

C:\Kalyx\MKPE\                    # System installation
├── v1.0.0\
│   └── bin\mkpe.exe
├── tools\
│   └── Monitor-MKPEIntegrity.ps1 ✅
└── audit\                         ✅
    ├── integrity.log
    ├── operations.log
    └── rejections.log
```

---

## Implementation Roadmap

### v1.0.0 (Current) ✅
- [x] Core engine
- [x] CLI tool
- [x] .mkpe format
- [x] Integration policy
- [x] Monitoring scripts

### v1.1.0 (Future)
- [ ] Attestation layer
- [ ] Enhanced audit logging
- [ ] Multi-signature support
- [ ] Cross-platform validation

### v1.2.0 (Future)
- [ ] Steganography layer
- [ ] Hardware key support (YubiKey/TPM)
- [ ] GUI for non-technical users

### v2.0.0 (Future)
- [ ] Language bindings (C++, Python, TypeScript)
- [ ] Network verification service
- [ ] Distributed ledger integration

---

## Design Principles

### 1. Core Purity
- Layer 1 (Core) **never changes** after freeze
- All enhancements go in higher layers
- New versions create new canonical artifacts

### 2. Separation of Concerns
- Each layer has one clear responsibility
- Layers communicate through defined interfaces
- No layer bypasses the layer below it

### 3. Opt-In Enhancement
- Attestation is optional
- Steganography is optional
- Core functionality works standalone

### 4. Verifiable at Every Layer
- Core: Cryptographic signatures
- Integration: Policy enforcement
- Attestation: Build reproducibility
- Steganography: Embedded proof extraction

---

## Security Considerations

### Attack Surface Per Layer

**Layer 1 (Core)**: Minimal
- Pure cryptographic operations
- No network access
- Deterministic behavior

**Layer 2 (Integration)**: Low
- Read-only policy enforcement
- Local logging only
- No external dependencies

**Layer 3 (Attestation)**: Medium
- System introspection
- Trusted build environment assumed
- Signature required

**Layer 4 (Steganography)**: Medium
- Media file parsing
- Must validate format integrity
- No execution of embedded data

### Trust Boundaries

```
Trusted:
  - Layer 1 (Core) - frozen, verified
  - Private signing keys
  - Local audit logs

Semi-Trusted:
  - Build environment (attestation)
  - Media file formats (stego)

Untrusted:
  - External .mkpe bundles (verify before trust)
  - Network sources
  - User-provided assets
```

---

## Best Practices for Integrators

1. **Always verify at Layer 1**
   - Call `mkpe verify` before trusting any bundle
   - Check manifest ID matches expected

2. **Enforce Layer 2 policy**
   - Parse `mkpe_integration.json` at startup
   - Follow required checks
   - Log all security events

3. **Use Layer 3 when reproducibility matters**
   - For release builds
   - For compliance requirements
   - For audit trails

4. **Use Layer 4 for persistent provenance**
   - When artifacts circulate outside your control
   - For media that gets copied/shared
   - For web publication

---

## Appendix: Example Integration

### Minimal (Core Only)

```rust
use morse_kirby_core::*;

// Generate keypair
let keypair = generate_keypair();

// Create and sign bundle
let proofs = create_recursive_proofs("project/", &keypair)?;
let bundle = create_proof_bundle(proofs, &keypair, None)?;
let mut manifest = Manifest::new(/*...*/);
manifest.sign(&keypair)?;

let archive = MkpeArchive::new(manifest, vec![bundle]);
archive.save("project.mkpe")?;

// Verify
let loaded = MkpeArchive::load("project.mkpe")?;
assert!(loaded.verify()?);
```

### Full Stack (All Layers)

```rust
// Layer 1: Core signing
create_mkpe_bundle("project/", &keypair, "project.mkpe")?;

// Layer 2: Policy enforcement
enforce_integration_policy("mkpe_integration.json")?;
log_operation("bundle_created", "project.mkpe")?;

// Layer 3: Attestation (future)
let attestation = generate_attestation(&archive)?;
sign_attestation(&attestation, &keypair)?;

// Layer 4: Steganography (future)
embed_in_media("cover.png", "project.mkpe", "cover_proven.png")?;
```

---

**End of Architecture Documentation**

This layered design ensures MKPE remains pure, extensible, and maintainable.

