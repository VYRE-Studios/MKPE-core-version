# MKPE Attestation Layer

**Status**: Implemented in v1.1.0
**Version**: v1.1.0
**Location**: `C:\mkpe\attestation\`

---

## Purpose

The attestation layer adds verifiable metadata about the **build environment** without modifying the core `.mkpe` format. It answers: "Where, when, and how was this built?"

---

## Architecture

```
build_attestation.json
 ├─ schema_version: "1.0"
 ├─ engine_manifest_id: "<uuid>"
 ├─ engine_version: "v1.0.0-mkpe"
 ├─ root_hash: "9b5041f701ba5279..."
 ├─ build_fingerprint:
 │   ├─ os: "Windows 10.0.26100"
 │   ├─ rustc_version: "1.81.0-stable"
 │   ├─ target_triple: "x86_64-pc-windows-msvc"
 │   ├─ compiler_flags: "--release"
 │   ├─ dependencies_hash: "sha256:..."
 │   ├─ cpu: "AMD Ryzen 9"
 │   └─ memory_gb: 64
 ├─ timestamp_utc: "2025-10-08T15:00:00Z"
 ├─ attested_by: "build_system_id"
 └─ signature: "<ed25519_signature>"
```

---

## CLI

### Generate Attestation
```bash
mkpe attest generate ./artifact \
  --key ./keys/mkpe_private.key \
  --bundle ./artifact.mkpe \
  --output build_attestation.json \
  --attested-by ci \
  --command "cargo build --release"
```

### Sign Attestation
The attestation is signed during generation.

### Verify Attestation
```bash
mkpe attest verify build_attestation.json \
  --subject ./artifact \
  --bundle ./artifact.mkpe \
  --public-key ./keys/mkpe_public.key
```

---

## Integration Points

### During Build

```
1. Compile MKPE core → mkpe_core.lib
2. Generate and sign attestation → build_attestation.json
3. Verify attestation against the artifact and trusted public key
4. Include in freeze package
```

### During Deployment

```
1. Load attestation
2. Verify signature
3. Check root_hash matches installed engine
4. Log attestation details
```

---

## Schema Definition

```json
{
  "$schema": "https://kalyx.internal/schemas/build_attestation.v1.json",
  "type": "object",
  "required": [
    "schema_version",
    "engine_manifest_id",
    "engine_version",
    "root_hash",
    "build_fingerprint",
    "timestamp_utc",
    "signature"
  ],
  "properties": {
    "schema_version": { "type": "string", "const": "1.0" },
    "engine_manifest_id": { "type": "string", "format": "uuid" },
    "engine_version": { "type": "string", "pattern": "^v\\d+\\.\\d+\\.\\d+-mkpe$" },
    "root_hash": { "type": "string", "pattern": "^[0-9a-f]+$" },
    "build_fingerprint": {
      "type": "object",
      "required": ["os", "rustc_version", "target_triple"],
      "properties": {
        "os": { "type": "string" },
        "rustc_version": { "type": "string" },
        "target_triple": { "type": "string" },
        "compiler_flags": { "type": "string" },
        "dependencies_hash": { "type": "string" },
        "cpu": { "type": "string" },
        "memory_gb": { "type": "number" }
      }
    },
    "timestamp_utc": { "type": "string", "format": "date-time" },
    "attested_by": { "type": "string" },
    "signature": { "type": "string" }
  }
}
```

---

## Security Model

### What Attestation Proves
- ✅ Build environment was recorded
- ✅ Attestation signed by authorized key
- ✅ Root hash matches engine bundle
- ✅ Timestamp is plausible

### What Attestation Does NOT Prove
- ❌ Build environment wasn't compromised
- ❌ Dependencies were trustworthy
- ❌ Compiler wasn't backdoored

**Attestation enables audit, not absolute trust**

---

## Future Enhancements

- [ ] Hardware-based attestation (TPM, SGX)
- [ ] Multi-party attestation (build witnessed by multiple systems)
- [ ] Reproducible build verification
- [ ] Continuous integration signature

---

## Implementation Checklist

- [ ] Define `mkpe_attest` CLI tool
- [ ] Implement attestation generation
- [ ] Implement attestation verification
- [ ] Add to build pipeline
- [ ] Update integration policy
- [ ] Document usage
- [ ] Add tests

---

**Status**: Implemented in v1.1.0



