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
 ├─ attestation_id: "<uuid>"
 ├─ subject_path: "./artifact"
 ├─ subject_kind: "file|directory"
 ├─ subject_sha256: "sha256..."
 ├─ bundle_manifest_id: "<optional .mkpe manifest id>"
 ├─ bundle_root_hash: "<optional .mkpe root hash>"
 ├─ build_fingerprint:
 │   ├─ user: "builder"
 │   ├─ platform: "Windows"
 │   ├─ hostname: "build-host"
 │   ├─ process_id: 1234
 │   ├─ architecture: "x86_64"
 │   ├─ mkpe_version: "1.1.0-mkpe"
 │   └─ working_directory: "C:\\repo"
 ├─ command: "cargo build --release"
 ├─ timestamp_utc: "2025-10-08T15:00:00Z"
 ├─ attested_by: "build_system_id"
 ├─ signer_public_key: "<ed25519_public_key>"
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
2. Verify signature with trusted public key
3. Recompute subject hash and compare it to `subject_sha256`
4. Verify linked `.mkpe` sidecar proves the same subject when a bundle is linked
5. Log attestation details
```

---

## Schema Definition

```json
{
  "$schema": "https://kalyx.internal/schemas/build_attestation.v1.json",
  "type": "object",
  "required": [
    "schema_version",
    "attestation_id",
    "subject_path",
    "subject_kind",
    "subject_sha256",
    "build_fingerprint",
    "timestamp_utc",
    "attested_by",
    "signer_public_key",
    "signature"
  ],
  "properties": {
    "schema_version": { "type": "string", "const": "1.0" },
    "attestation_id": { "type": "string", "format": "uuid" },
    "subject_path": { "type": "string" },
    "subject_kind": { "type": "string", "enum": ["file", "directory"] },
    "subject_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "bundle_manifest_id": { "type": ["string", "null"], "format": "uuid" },
    "bundle_root_hash": { "type": ["string", "null"], "pattern": "^[0-9a-f]+$" },
    "build_fingerprint": {
      "type": "object",
      "required": ["user", "platform", "hostname", "process_id", "architecture", "mkpe_version", "working_directory"],
      "properties": {
        "user": { "type": "string" },
        "platform": { "type": "string" },
        "hostname": { "type": "string" },
        "process_id": { "type": "integer" },
        "architecture": { "type": "string" },
        "mkpe_version": { "type": "string" },
        "working_directory": { "type": "string" }
      }
    },
    "command": { "type": ["string", "null"] },
    "timestamp_utc": { "type": "string", "format": "date-time" },
    "attested_by": { "type": "string" },
    "signer_public_key": { "type": "string" },
    "signature": { "type": "string" }
  }
}
```

---

## Security Model

### What Attestation Proves
- ✅ Build environment was recorded
- ✅ Attestation signed by authorized key
- ✅ Subject hash matches the current artifact
- ✅ Linked `.mkpe` sidecar proves the same subject when provided
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



