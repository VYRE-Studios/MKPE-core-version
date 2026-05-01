# Morse-Kirby Provenance Engine (MKPE) – Integration & Usage Guide

**Version**: v1.1.0-mkpe
**Manifest ID**: `6260a764-7901-4997-9a85-898d728e760d`  
**Root Hash**: `9b5041f701ba5279...`

This guide defines how MKPE must be integrated and used by all host applications.

---

## Core Ideas

- **`.mkpe`** = binary-JSON hybrid bundle proving origin and integrity
- **Canonical Engine** (`v1.0.0-mkpe`) is frozen; all later versions must reference it
- Every artifact that claims provenance must be signed through the engine's API or CLI
- **Core Principle**: *"Every verified object carries its own truth."*

---

## Required Integration Steps

### 1. Startup Verification

**REQUIRED** – Call on application startup:

```powershell
mkpe.exe verify C:\mkpe\mkpe_core_v1.0.0.mkpe --expect-manifest-id=6260a764-7901-4997-9a85-898d728e760d
```

**Behavior**:
- If verification **passes**: Continue normal operation
- If verification **fails**: 
  - Abort provenance mode
  - Append to `C:\Kalyx\MKPE\audit\integrity.log`
  - Notify administrator

### 2. Bundle → Sign → Verify Workflow

**Canonical export workflow**:

```bash
# 1. Create bundle from directory or file
mkpe.exe bundle <path> --output <name>.mkpe

# 2. Sign with project key
mkpe.exe sign <name>.mkpe -k project.key

# 3. Verify signature
mkpe.exe verify <name>.mkpe
```

**Example**:
```bash
mkpe.exe bundle C:\workspace\myproject --output myproject_v1.0.mkpe
mkpe.exe sign myproject_v1.0.mkpe -k ~/.keys/project.key
mkpe.exe verify myproject_v1.0.mkpe --json --output verify_result.json
```

### 3. Audit Logging

**Write to these locations**:

- **Integrity Log**: `C:\Kalyx\MKPE\audit\integrity.log`
  - Engine verification results
  - Hash mismatch events
  
- **Operations Log**: `C:\Kalyx\MKPE\audit\operations.log`
  - Successful bundle creation
  - Successful verification
  - Normal operations
  
- **Rejections Log**: `C:\Kalyx\MKPE\audit\rejections.log`
  - Failed verifications
  - Rejected imports
  - Security events

**Log Format**:
```json
{
  "timestamp_utc": "2025-10-08T15:00:00Z",
  "action": "verify",
  "actor": "user@hostname",
  "artifact": "project_v1.mkpe",
  "result": "success|failure",
  "details": "Additional context"
}
```

### 4. Attestation & Steganography

**Attestation**:
- Generate `build_attestation.json` with build metadata, subject hash, and optional `.mkpe` bundle linkage.
- Verify attestation with the expected public key before trusting build provenance.
- See `C:\mkpe\attestation\` for schema and workflow.

```powershell
mkpe.exe attest generate <artifact> --key <private_key> --bundle <artifact>.mkpe --output build_attestation.json
mkpe.exe attest verify build_attestation.json --subject <artifact> --bundle <artifact>.mkpe --public-key <public_key>
```

**Steganography**:
- Apply watermarks **after** `.mkpe` creation
- Never modify `.mkpe` internals
- See `C:\mkpe\stego\` for tools (when implemented)

---

## Versioning & Keys

### Engine Key
- **Storage**: Offline (HSM, USB, encrypted vault)
- **Usage**: Sign canonical engine artifacts only
- **Rotation**: Requires new major version

### Project Keys
- **Storage**: Per user/project
- **Format**: Ed25519 keypair
- **Rotation**: On compromise or annually
- **Generation**: `mkpe.exe keygen --output project.key`

### Version Upgrades
- Engine major version changes (`v1.x` → `v2.x`) require:
  - New canonical manifest
  - New self-signed `.mkpe`
  - Published migration guide
  - Dual signatures during transition

---

## Failure Policy

### Verification Failure on Import

**Action**:
1. Block the asset from import
2. Log event to `rejections.log`
3. Return error to user
4. **DO NOT** auto-retry or auto-repair

**Example Log Entry**:
```json
{
  "timestamp_utc": "2025-10-08T16:30:00Z",
  "action": "import_rejected",
  "artifact": "untrusted_bundle.mkpe",
  "reason": "signature_verification_failed",
  "details": "Ed25519 signature invalid"
}
```

### Engine Hash Mismatch on Startup

**Action**:
1. Disable provenance mode
2. Log to `integrity.log`
3. Alert administrator via configured channel
4. Continue non-provenance operations if safe

---

## Machine-Readable Policy

See `mkpe_integration.json` for:
- Exact startup check commands
- Command paths and arguments
- Audit log locations
- Policy flags

Applications should parse this JSON at startup and follow the defined checks.

---

## Command Reference

### Generate Keypair
```bash
mkpe.exe keygen --output ~/.keys/myproject.key
```

### Create Bundle
```bash
mkpe.exe bundle C:\workspace\project --output project_v1.mkpe
```

### Sign Bundle
```bash
mkpe.exe sign project_v1.mkpe -k ~/.keys/myproject.key
```

### Verify Bundle
```bash
mkpe.exe verify project_v1.mkpe --json --output verify.json
```

### Inspect Bundle
```bash
mkpe.exe inspect project_v1.mkpe --export-manifest manifest.json
```

### Hash File
```bash
mkpe.exe hash myfile.txt
```

### Validate C-DNA Schema
```bash
mkpe.exe validate-cdna schema.cdna.json --proof -k project.key
```

### Generate Build Attestation
```bash
mkpe.exe attest generate C:\workspace\project --key project.key --bundle project.mkpe --output build_attestation.json --attested-by ci
```

### Verify Build Attestation
```bash
mkpe.exe attest verify build_attestation.json --subject C:\workspace\project --bundle project.mkpe --public-key project_public.key
```

---

## Integration Checklist

### Developers

- [ ] Engine verification at app startup implemented
- [ ] Bundle creation flow integrated into export
- [ ] Verification flow integrated on import
- [ ] Local audit logs enabled and writing
- [ ] Error handling for verification failures
- [ ] Key management UI/workflow added
- [ ] Documentation updated with MKPE usage

### DevOps

- [ ] Engine installed to canonical location
- [ ] Integrity monitor scheduled daily
- [ ] Audit logs rotated and backed up
- [ ] Key storage secured (HSM/vault)
- [ ] Monitoring alerts configured

### Optional Enhancements

- [ ] Attestation consumption code
- [ ] Steganography pipeline (post-bundle)
- [ ] Hardware token integration (YubiKey/TPM)
- [ ] Multi-signature workflows

---

## Security Best Practices

### Key Storage

**Engine Key** (offline recommended):
- HSM (Hardware Security Module)
- Encrypted USB drive
- Air-gapped system
- Never commit to version control

**Project Keys** (per-user):
- OS keychain (macOS Keychain, Windows Credential Manager)
- Encrypted on disk with strong passphrase
- Hardware token for high-trust deployments
- Rotate on compromise or annually

### Operations

1. **Never** auto-update the engine without verification
2. **Never** sign bundles automatically without review
3. **Always** verify before trusting imported artifacts
4. **Always** log security events
5. **Require** explicit user action for key operations

---

## Example Integration (Rust)

```rust
use std::process::Command;
use std::fs;

fn verify_mkpe_artifact(path: &str) -> Result<bool, String> {
    let output = Command::new("C:\\mkpe\\cli\\target\\release\\mkpe.exe")
        .args(&["verify", path, "--json"])
        .output()
        .map_err(|e| format!("Failed to spawn mkpe: {}", e))?;

    if !output.status.success() {
        // Log rejection
        log_rejection(path, &String::from_utf8_lossy(&output.stderr));
        return Ok(false);
    }

    // Log success
    log_operation("verify", path, "success");
    Ok(true)
}

fn log_rejection(artifact: &str, reason: &str) {
    let entry = format!(
        "{{\"timestamp_utc\":\"{}\",\"action\":\"verify_failed\",\"artifact\":\"{}\",\"reason\":\"{}\"}}",
        chrono::Utc::now().to_rfc3339(),
        artifact,
        reason
    );
    let _ = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("C:\\Kalyx\\MKPE\\audit\\rejections.log")
        .and_then(|mut f| writeln!(f, "{}", entry));
}
```

---

## Example Integration (PowerShell)

```powershell
# Load integration policy
$policy = Get-Content "C:\mkpe\docs\mkpe_integration.json" | ConvertFrom-Json

# Run startup check
$check = $policy.required_startup_checks[0]
$result = & $check.command[0] @($check.command[1..($check.command.Length-1)])

if ($LASTEXITCODE -ne $check.success_exit) {
    Add-Content $policy.audit_paths.integrity_log `
        "$(Get-Date -Format o) STARTUP_FAIL - Engine verification failed"
    # Disable provenance mode
    $global:ProvenanceEnabled = $false
} else {
    Add-Content $policy.audit_paths.operations_log `
        "$(Get-Date -Format o) STARTUP_OK - Engine verified"
    $global:ProvenanceEnabled = $true
}
```

---

## Troubleshooting

### "Verification failed" on startup

**Cause**: Engine files may have been modified or corrupted

**Solution**:
1. Run `Monitor-MKPEIntegrity.ps1` manually
2. Compare hashes against `canonical_hash.txt`
3. Reinstall from `MKPE_v1.0.0_FROZEN.zip`
4. Verify installation: `mkpe.exe version`

### "Signature verification failed" on import

**Cause**: Bundle was modified, signed with wrong key, or corrupted

**Solution**:
1. Verify bundle integrity: `mkpe.exe inspect bundle.mkpe`
2. Check public key matches: compare with sender's published key
3. Request re-export and re-signature from source
4. **Never** try to repair or re-sign another party's bundle

### "Key not found" when signing

**Cause**: Key file path incorrect or key not generated

**Solution**:
1. Verify key exists: `Test-Path project.key`
2. Generate if needed: `mkpe.exe keygen --output project.key`
3. Check file permissions
4. Verify key format (Ed25519, base64-encoded)

---

## Contact & Change Control

**Canonical Source**: `C:\mkpe\`  
**Documentation**: `C:\mkpe\docs\`  
**Audit Logs**: `C:\Kalyx\MKPE\audit\`

All changes to integration rules must be:
1. Recorded in freeze manifest
2. Signed with engine key
3. Documented in changelog
4. Published to integrators

For enterprise deployments, maintain a signed Change Log with each engine version.

---

## Appendix: File Locations

### Engine Files
```
C:\mkpe\
├── cli\target\release\mkpe.exe          # CLI tool
├── core\target\release\morse_kirby_core.lib  # Library
├── mkpe_core_v1.0.0.mkpe                # Self-signed engine
├── canonical_hash.txt                    # Hash tree
└── canonical_hash.mkpe                   # Signed hashes
```

### Documentation
```
C:\mkpe\docs\
├── README_USAGE.md                       # This file
├── mkpe_integration.json                 # Machine policy
├── format_spec_v1.0.md                   # Binary format
└── FREEZE_MANIFEST_v1.0.0.md            # Freeze cert
```

### System Installation
```
C:\Kalyx\MKPE\
├── v1.0.0\
│   └── bin\mkpe.exe                      # Installed CLI
├── tools\
│   └── Monitor-MKPEIntegrity.ps1         # Monitor script
└── audit\
    ├── integrity.log
    ├── operations.log
    └── rejections.log
```

---

**End of Integration Guide**

This document is part of the MKPE v1.0.0 canonical freeze.  
For updates, see the freeze manifest and changelog.



