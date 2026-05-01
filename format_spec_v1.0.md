# .mkpe File Format Specification v1.0

**Status**: ✅ Canonical  
**Version**: 1.0.0  
**Date**: October 8, 2025  
**Engine**: Morse-Kirby Provenance Engine (MKPE)

---

## Overview

The `.mkpe` file format is a self-contained, cryptographically signed provenance bundle that combines:
- Human-readable JSON manifest
- Binary Merkle proof tree
- Ed25519 digital signatures
- Corruption detection via CRC32

**Core Principle**: *"Every verified object carries its own truth."*

---

## Binary Structure

### Complete Layout

```
┌─────────────────────────────────────┐
│  Header (32 bytes)                  │  Fixed structure
├─────────────────────────────────────┤
│  Manifest Section (Variable)        │  JSON, plaintext
├─────────────────────────────────────┤
│  Proof Section (Variable)           │  Binary Merkle tree
├─────────────────────────────────────┤
│  Signature Block (96 bytes)         │  Ed25519 key + sig
├─────────────────────────────────────┤
│  Footer (8 bytes)                   │  Magic + CRC32
└─────────────────────────────────────┘
```

---

## Section 1: Header (32 bytes)

### Field Layout

| Offset | Size | Type    | Field            | Description                                    |
|--------|------|---------|------------------|------------------------------------------------|
| 0x00   | 4 B  | ASCII   | **Magic**        | "MKPE" (0x4D 0x4B 0x50 0x45)                  |
| 0x04   | 1 B  | u8      | **Version**      | Format version: `0x01`                         |
| 0x05   | 1 B  | u8      | **Flags**        | Bit 0: Encrypted, Bit 1: Compressed           |
| 0x06   | 8 B  | u64 LE  | **Manifest Size**| Length of manifest section in bytes            |
| 0x0E   | 8 B  | u64 LE  | **Proof Size**   | Length of proof section in bytes               |
| 0x16   | 8 B  | u64 LE  | **Sig Size**     | Length of signature block (always 96)          |
| 0x1E   | 2 B  | u16     | **Reserved**     | Future use, must be `0x0000`                   |

### Flags Bitmask

| Bit | Value | Meaning              | Status in v1.0 |
|-----|-------|----------------------|----------------|
| 0   | 0x01  | Proof data encrypted | Not implemented|
| 1   | 0x02  | Proof data compressed| Not implemented|
| 2-7 | -     | Reserved             | Must be 0      |

### Example (Hexdump)

```
00000000: 4d 4b 50 45 01 00 4a 01  00 00 00 00 00 00 04 00  MKPE..J.........
00000010: 00 00 00 00 00 00 60 00  00 00 00 00 00 00 00 00  ......`.........
          ^^^^^^^^^^^^^ ^^^^  ^^^^  ^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^
          Magic         Ver   Flags Manifest size    Proof size
```

---

## Section 2: Manifest (Variable, JSON)

### Schema

```json
{
  "schema_version": "1.0.0",
  "engine_version": "1.0.0-mkpe",
  "manifest_id": "<uuid>",
  "system_fingerprint": {
    "user": "string",
    "platform": "Windows|Linux|Darwin",
    "hostname": "string",
    "process_id": uint32,
    "mkpe_version": "1.0.0-mkpe",
    "timestamp": "ISO8601"
  },
  "bundle_root_hash": "hex(sha256)",
  "proof_count": uint,
  "sealed_timestamp": "ISO8601",
  "verifier_public_key": "base64(32 bytes)",
  "signature": "base64(64 bytes)",
  "parent_manifest_id": "uuid | null",
  "metadata": {
    // Optional user-defined key-value pairs
  }
}
```

### Encoding Rules

1. **Canonical JSON**: Use compact encoding (no extra whitespace) for reproducible hashes
2. **UTF-8**: All strings must be UTF-8 encoded
3. **ISO 8601**: Timestamps use `YYYY-MM-DDTHH:MM:SSZ` format
4. **Base64**: Standard encoding (RFC 4648) for binary data
5. **Hex**: Lowercase hexadecimal for hashes

---

## Section 3: Proof Data (Variable, Binary)

### Structure

```
┌──────────────────────┐
│ Count (4 bytes)      │  u32 LE: number of proof hashes
├──────────────────────┤
│ Hash 1 (32 bytes)    │  SHA-256 binary
├──────────────────────┤
│ Hash 2 (32 bytes)    │  SHA-256 binary
├──────────────────────┤
│ ...                  │
├──────────────────────┤
│ Hash N (32 bytes)    │  SHA-256 binary
└──────────────────────┘
```

### Layout Details

- **Count**: Little-endian u32, number of hashes that follow
- **Hashes**: Raw 32-byte SHA-256 digests (not hex-encoded)
- **Order**: Hashes appear in the order they were added to the bundle
- **Total Size**: `4 + (32 × count)` bytes

### Example (5 hashes)

```
Offset 0x00: 05 00 00 00                           // count = 5
Offset 0x04: [32 bytes hash 1]
Offset 0x24: [32 bytes hash 2]
Offset 0x44: [32 bytes hash 3]
Offset 0x64: [32 bytes hash 4]
Offset 0x84: [32 bytes hash 5]
Total size: 164 bytes (0xA4)
```

---

## Section 4: Signature Block (96 bytes)

### Structure

```
┌──────────────────────────┐
│ Public Key (32 bytes)    │  Ed25519 public key
├──────────────────────────┤
│ Signature (64 bytes)     │  Ed25519 signature
└──────────────────────────┘
```

### Signature Calculation

The signature is computed over:

```
SHA256(manifest_bytes || proof_data_bytes)
```

### Verification Process

```rust
let data_to_verify = sha256(&[manifest, proof_data]);
ed25519_verify(public_key, signature, data_to_verify)
```

---

## Section 5: Footer (8 bytes)

### Field Layout

| Offset   | Size | Type   | Field       | Description                           |
|----------|------|--------|-------------|---------------------------------------|
| EOF - 8  | 4 B  | ASCII  | **Magic**   | "EPKM" (reverse of MKPE)             |
| EOF - 4  | 4 B  | u32 LE | **CRC32**   | Checksum of header + manifest length |

### CRC32 Calculation

```
CRC32(header_bytes || manifest_size_as_u64_le)
```

Uses polynomial `0xEDB88320` (CRC-32/ISO-HDLC).

### Purpose

- **Quick Validation**: Detect file corruption without full verification
- **File Identification**: Scan files from the end to identify .mkpe format
- **Integrity Check**: Ensure header and manifest size haven't been tampered with

---

## Parsing Algorithm

### Read Process

```rust
fn parse_mkpe(file_path: Path) -> Result<MkpeArchive> {
    let mut file = File::open(file_path)?;
    
    // 1. Read header (32 bytes)
    let header = read_header(&mut file)?;
    verify_magic(&header.magic, b"MKPE")?;
    
    // 2. Read manifest (header.manifest_size bytes)
    let manifest_bytes = read_exact(&mut file, header.manifest_size)?;
    let manifest = parse_json(&manifest_bytes)?;
    
    // 3. Read proof data (header.proof_size bytes)
    let proof_bytes = read_exact(&mut file, header.proof_size)?;
    let proofs = parse_proofs(&proof_bytes)?;
    
    // 4. Read signature block (header.signature_size bytes, should be 96)
    let sig_block = read_exact(&mut file, header.signature_size)?;
    let (public_key, signature) = parse_signature(&sig_block)?;
    
    // 5. Read footer (8 bytes)
    let footer = read_footer(&mut file)?;
    verify_magic(&footer.magic, b"EPKM")?;
    
    // 6. Verify CRC32
    let expected_crc = calculate_crc32(&header, manifest_bytes.len());
    if expected_crc != footer.crc32 {
        return Err("CRC32 mismatch");
    }
    
    // 7. Verify signature
    let data_hash = sha256(&[manifest_bytes, proof_bytes]);
    ed25519_verify(public_key, signature, data_hash)?;
    
    Ok(MkpeArchive { manifest, proofs, ... })
}
```

---

## Validation Rules

### Must Pass

1. ✅ **Magic Header**: First 4 bytes must be "MKPE"
2. ✅ **Version**: Byte 4 must be `0x01` for this specification
3. ✅ **Reserved Bits**: Flags bits 2-7 and reserved field must be zero
4. ✅ **Size Consistency**: Actual section sizes must match header declarations
5. ✅ **CRC32 Match**: Footer CRC must match calculated value
6. ✅ **Footer Magic**: Last 8 bytes must start with "EPKM"
7. ✅ **Signature Valid**: Ed25519 signature must verify against public key
8. ✅ **JSON Valid**: Manifest must be parseable as valid JSON
9. ✅ **Proof Count**: Number of hashes must match manifest's `proof_count`

### Should Pass (Recommendations)

- Manifest should include `schema_version` and `engine_version`
- Timestamps should be in valid ISO 8601 format
- Public key in manifest should match signature block's public key
- Root hash in manifest should match Merkle root of proof hashes

---

## File Extension Registration

### Windows Registry

```registry
HKEY_CLASSES_ROOT\.mkpe
  (Default) = "MKPEFile"

HKEY_CLASSES_ROOT\MKPEFile
  (Default) = "MKPE Provenance Bundle"
  
HKEY_CLASSES_ROOT\MKPEFile\shell\verify\command
  (Default) = "\"C:\Kalyx\MKPE\v1.0.0\bin\mkpe.exe\" verify \"%1\""
```

### MIME Type

```
application/x-mkpe
```

### macOS/Linux

```desktop
[Desktop Entry]
Type=Application
Name=MKPE Verifier
Exec=mkpe verify %f
MimeType=application/x-mkpe;
```

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| **Tampering** | Ed25519 signature breaks on any modification |
| **Corruption** | CRC32 detects accidental bit flips |
| **Replay** | Timestamps and parent linking prevent reuse |
| **Forgery** | Private key required to create valid signatures |
| **Collision** | SHA-256 provides 128-bit collision resistance |

### Best Practices

1. **Keep Private Keys Secure**: Store in encrypted locations, never commit to repos
2. **Verify Before Trust**: Always call `mkpe verify` before using bundles
3. **Check Timestamps**: Reject bundles with future or suspicious timestamps
4. **Validate Chain**: Verify parent signatures when using chained bundles
5. **Use Canonical JSON**: Ensure manifest hashing is deterministic

---

## Version History

| Version | Date       | Changes |
|---------|------------|---------|
| 1.0.0   | 2025-10-08 | Initial canonical release |

---

## Implementation Reference

**Reference Implementation**: `morse_kirby_core` v1.0.0-mkpe

- Language: Rust 2021 edition
- Source: `C:\mkpe\core\`
- CLI: `C:\mkpe\cli\target\release\mkpe.exe`

---

## Appendix A: Example File

### Minimal .mkpe File

```
Offset  Content
------  -------
0x0000  4D 4B 50 45 01 00 ...  [Header: 32 bytes]
0x0020  7B 22 73 63 68 65 ...  [Manifest: JSON]
0x01A0  03 00 00 00 3A 4B ...  [Proofs: 3 hashes]
0x0204  A7 3F 9C 2D ... ...  [Signature: 96 bytes]
0x0264  45 50 4B 4D 7F 2A ...  [Footer: 8 bytes]
```

### Size Calculation

```
Total = 32 (header)
      + manifest_size
      + proof_size (4 + 32×count)
      + 96 (signature)
      + 8 (footer)
```

---

**End of Specification**

This document defines the canonical .mkpe format v1.0.  
All implementations must conform to this specification.

**Signed**: MKPE Development Team  
**Hash**: To be calculated and included in freeze

