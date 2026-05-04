# MKPE Provenance Standards Compliance Plan

**Objective:** Achieve industry-standard provenance capabilities (Sigstore, SLSA Level 2) while maintaining MKPE's simplicity and portability.

**Approach:** Phased implementation based on severity, security impact, and dependencies.

---

## Phase 1: Critical Security Fixes (Immediate)

### 1.1 Replay Attack Protection ⚠️ **CRITICAL**

**Why:** Without this, attackers can reuse stale attestations to impersonate legitimate artifacts.

| Aspect | Detail |
|--------|--------|
| **Effort** | Low (1-2 days) |
| **Severity** | Security - allows replay attacks |
| **Risk if not done** | High |

**Implementation:**

1. Add optional `nonce` field to attestation and manifest:
   ```rust
   // In Manifest struct
   pub nonce: Option<u64>,
   
   // Verification option
   pub min_timestamp: Option<DateTime<Utc>>,
   ```

2. Add nonce generation during bundle creation:
   ```rust
   // When creating manifest, optionally include timestamp nonce
   let nonce = std::time::SystemTime::now()
       .duration_since(UNIX_EPOCH)
       .map(|d| d.as_nanos() as u64);
   ```

3. Implement nonce verification:
   ```rust
   pub fn verify_nonce(&self, expected: u64) -> bool {
       self.nonce.map(|n| n >= expected).unwrap_or(false)
   }
   ```

4. Add monotonic timestamp validation (optional):
   ```rust
   // Verify manifest_timestamp >= previous_manifest_timestamp
   ```

**Deliverables:**
- [x] Add `nonce` field to `Manifest`
- [x] Add `nonce` field to `BuildAttestation`
- [x] Add `verify_nonce()` method
- [x] Add timestamp ordering verification
- [x] Add tests for nonce verification

---

### 1.2 Key Rotation Infrastructure ⚠️ **CRITICAL**

**Why:** If current key is compromised, all future bundles are untrustworthy. No recovery path exists.

| Aspect | Detail |
|--------|--------|
| **Effort** | Medium (3-5 days) |
| **Severity** | Security - key compromise = system failure |
| **Risk if not done** | Critical |

**Implementation:**

1. Add key metadata to manifest:
   ```rust
   pub struct KeyMetadata {
       pub key_id: String,           // Hash of public key for identification
       pub version: u32,              // Key version for rotation
       pub created_at: DateTime<Utc>,
       pub expires_at: Option<DateTime<Utc>>,
       pub predecessor_key_id: Option<String>,  // For rotation chain
   }
   ```

2. Extend Manifest with key tracking:
   ```rust
   pub key_metadata: Option<KeyMetadata>,
   pub previous_manifest_id: Option<String>,  // Chain to previous manifest
   ```

3. Implement key version verification:
   ```rust
   impl Manifest {
       pub fn verify_key_rotation(
           &self,
           trusted_keys: &BTreeMap<String, PublicKey>,
       ) -> Result<bool> {
           // 1. Check key_id is in trusted_keys
           // 2. Verify version is acceptable
           // 3. If predecessor exists, verify rotation chain
           // 4. Check expiration if set
       }
   }
   ```

4. Create revocation list support:
   ```rust
   pub struct RevocationList {
       pub revoked_keys: Vec<String>,  // key_ids
       pub timestamp: DateTime<Utc>,
   }
   ```

**Deliverables:**
- [x] Add `KeyMetadata` struct
- [x] Add key version tracking to `Manifest`
- [x] Implement rotation chain verification
- [x] Add revocation list structure
- [x] Add revocation check to verification
- [x] Add key rotation tests

---

## Phase 2: Trust Infrastructure (Short-term)

### 2.1 Freshness Attestation ✓ **HIGH**

**Why:** Verifiers need to know provenance data is current, not years old.

| Aspect | Detail |
|--------|--------|
| **Effort** | Low (2 days) |
| **Dependencies** | Phase 1.1 (nonce) |
| **Severity** | Trust - stale data is unreliable |

**Implementation:**

1. Enhance timestamp handling:
   ```rust
   pub struct FreshnessStamp {
       pub created_at: DateTime<Utc>,
       pub nonce: u64,           // Monotonically increasing
       pub previous_hash: String, // Links to previous attestation
   }
   ```

2. Add genesis manifest support:
   ```rust
   // First manifest in chain has no predecessor
   pub fn is_genesis(&self) -> bool {
       self.previous_manifest_id.is_none()
   }
   ```

3. Implement attestation chain verification:
   ```rust
   pub fn verify_chain(&self, chain: &[Manifest]) -> Result<bool> {
       for (i, manifest) in chain.iter().enumerate() {
           if i > 0 {
               // Verify previous_manifest_id matches
               let prev = &chain[i - 1];
               if manifest.previous_manifest_id.as_ref() != Some(&prev.manifest_id) {
                   return Err(MkpeError::VerificationFailed("Chain broken".into()));
               }
               // Verify nonce is monotonically increasing
               if manifest.nonce <= prev.nonce {
                   return Err(MkpeError::VerificationFailed("Nonce not fresh".into()));
               }
           }
           manifest.verify()?;
       }
       Ok(true)
   }
   ```

**Deliverables:**
- [x] Add `FreshnessStamp` struct
- [x] Implement chain verification
- [x] Add genesis manifest detection
- [x] Add freshness tests

---

### 2.2 Manifest Chaining ✓ **HIGH**

**Why:** Creates audit trail and enables freshness verification.

| Aspect | Detail |
|--------|--------|
| **Effort** | Low (2 days) |
| **Dependencies** | Phase 1.2 (key metadata) |
| **Severity** | Trust - enables verification |

**Implementation:**

1. Add chain fields:
   ```rust
   pub previous_manifest_id: Option<String>,
   pub chain_depth: u32,
   ```

2. Implement chain validation:
   ```rust
   pub fn validate_chain(&self, root_id: &str) -> Result<bool> {
       let mut current = self;
       let mut depth = 0u32;
       
       while let Some(prev_id) = &current.previous_manifest_id {
           depth += 1;
           // Load and verify previous manifest
           let prev = load_manifest(prev_id)?;
           prev.verify()?;
           current = Box::new(prev);
       }
       
       // Verify root matches
       if current.manifest_id != root_id {
           return Err(MkpeError::VerificationFailed("Root mismatch".into()));
       }
       
       Ok(true)
   }
   ```

**Deliverables:**
- [x] Add chain fields to Manifest
- [x] Implement chain traversal
- [x] Add root verification
- [x] Add chain validation tests

---

## Phase 3: Trust Infrastructure (Medium-term)

### 3.1 Transparency Log Integration ⚠️ **HIGH**

**Why:** Without public logging, there's no way to verify "this bundle was recorded at this time."

| Aspect | Detail |
|--------|--------|
| **Effort** | High (1-2 weeks) |
| **Severity** | Trust - required for auditability |
| **Alternative** | Lightweight internal audit trail |

**Implementation Options:**

#### Option A: External Integration (Sigstore-like)
```
Requires: External transparency log server
Pros: Industry standard, cross-org verification
Cons: Infrastructure dependency
```

#### Option B: Embedded Merkle Audit Trail
```
Requires: None (local only)
Pros: Self-contained, works offline
Cons: Less valuable without external verification
```

**Recommendation:** Implement Option B first (simpler), design for Option A later.

**Implementation (Embedded):**

```rust
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub manifest_id: String,
    pub bundle_hash: String,
    pub operation: String,  // "created", "updated", "verified"
}

pub struct AuditLog {
    pub entries: Vec<AuditEntry>,
    pub merkle_root: String,
}

impl AuditLog {
    pub fn append(&mut self, entry: AuditEntry) {
        let entry_hash = sha256(serde_json::to_vec(&entry).unwrap());
        self.entries.push(entry);
        self.merkle_root = build_merkle_root(&[
            self.merkle_root,
            entry_hash,
        ]);
    }
    
    pub fn verify(&self) -> bool {
        // Recompute merkle root and verify
        let hashes: Vec<String> = self.entries.iter()
            .map(|e| sha256(serde_json::to_vec(e).unwrap()))
            .collect();
        build_merkle_root(&hashes) == self.merkle_root
    }
}
```

**Deliverables:**
- [x] Add `AuditEntry` struct
- [x] Add `AuditLog` struct
- [x] Implement merkle-based audit trail
- [x] Add verification for audit integrity
- [x] Add audit log tests

---

### 3.2 Policy Engine ✓ **MEDIUM**

**Why:** Complex organizations need rules beyond "valid signature."

| Aspect | Detail |
|--------|--------|
| **Effort** | Medium (3-5 days) |
| **Severity** | Capability - enables enterprise use |
| **Dependencies** | Phase 1 (key rotation) |

**Implementation:**

```rust
pub enum PolicyCondition {
    KeyVersion { min: u32 },
    TimestampRange { min: DateTime<Utc>, max: DateTime<Utc> },
    KeyId { allowed: Vec<String> },
    ChainDepth { min: u32 },
    BundleHash { expected: String },
}

pub struct Policy {
    pub name: String,
    pub conditions: Vec<PolicyCondition>,
    pub require_all: bool,  // AND vs OR
}

impl Policy {
    pub fn evaluate(&self, manifest: &Manifest) -> bool {
        let results: Vec<bool> = self.conditions.iter()
            .map(|c| self.check_condition(c, manifest))
            .collect();
        
        if self.require_all {
            results.iter().all(|r| *r)
        } else {
            results.iter().any(|r| *r)
        }
    }
    
    fn check_condition(&self, cond: &PolicyCondition, manifest: &Manifest) -> bool {
        match cond {
            PolicyCondition::KeyVersion { min } => {
                manifest.key_metadata.as_ref()
                    .map(|k| k.version >= *min)
                    .unwrap_or(false)
            }
            // ... other conditions
        }
    }
}

pub struct PolicyEngine {
    pub policies: Vec<Policy>,
}

impl PolicyEngine {
    pub fn verify(&self, manifest: &Manifest) -> Result<bool> {
        for policy in &self.policies {
            if !policy.evaluate(manifest) {
                return Err(MkpeError::PolicyViolation(policy.name.clone()));
            }
        }
        Ok(true)
    }
}
```

**Deliverables:**
- [x] Add `Policy` struct
- [x] Add `PolicyEngine` struct
- [x] Implement condition types
- [x] Add policy evaluation
- [x] Add policy loading from config
- [x] Add policy tests

---

## Phase 4: Build Provenance (Medium-term)

### 4.1 SLSA-like Build Attestations ⚠️ **MEDIUM**

**Why:** Current MKPE only attests "content matches" but not "how was this built?"

| Aspect | Detail |
|--------|--------|
| **Effort** | Medium (1 week) |
| **Severity** | Capability - enables supply chain security |
| **Target** | SLSA Level 2 |

**Implementation:**

```rust
pub struct BuildAttestation {
    // Existing fields
    pub subject_path: PathBuf,
    pub subject_sha256: String,
    pub attestation_id: String,
    pub timestamp: DateTime<Utc>,
    
    // NEW: Build provenance
    pub build_info: BuildInfo,
}

pub struct BuildInfo {
    pub builder_id: String,           // Who built this
    pub build_type: String,           // "docker", "cargo", "npm", etc.
    pub build_definition: String,      // What was used to build
    pub source_repository: Option<String>,
    pub source_commit: Option<String>,
    pub dependencies: Vec<Dependency>,
    pub environment: HashMap<String, String>,
}

pub struct Dependency {
    pub name: String,
    pub version: String,
    pub source: String,  // "crates.io", "npm", etc.
    pub integrity: String,  // Hash of dependency
}

impl BuildAttestation {
    pub fn to_slsa_predicate(&self) -> serde_json::Value {
        serde_json::json!({
            "buildType": self.build_info.build_type,
            "builder": { "id": self.build_info.builder_id },
            "buildDefinition": {
                "buildType": self.build_info.build_type,
                "repository": self.build_info.source_repository,
                "commit": self.build_info.source_commit,
            },
            "runDetails": {
                "builder": { "id": self.build_info.builder_id },
                "metadata": {
                    "invocationId": self.attestation_id,
                    "startedOn": self.timestamp.to_rfc3339(),
                }
            }
        })
    }
}
```

**Deliverables:**
- [x] Add `BuildInfo` struct
- [x] Add `Dependency` struct
- [x] Extend `BuildAttestation`
- [x] Add SLSA predicate generation
- [x] Add build attestation tests

---

## Phase 5: Interoperability (Long-term)

### 5.1 DSSE Envelope Support ✓ **LOW**

**Why:** Industry standard envelope format for attestations.

| Aspect | Detail |
|--------|--------|
| **Effort** | Medium (3 days) |
| **Severity** | Interoperability |
| **Target** | Sigstore compatibility |

**Implementation:**

```rust
use serde::{Deserialize, Serialize};

/// DSSE (Dead Simple Signing Envelope) format
/// https://github.com/secure-systems-lab/dsse
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DSSEEnvelope {
    pub payload: String,           // Base64-encoded JSON
    pub payload_type: String,       // "application/vnd.slsa-provenance+json"
    pub signatures: Vec<DSSE签名>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DSSE签名 {
    pub keyid: String,
    pub sig: String,  // Base64-encoded signature
}

impl DSSEEnvelope {
    pub fn from_manifest(manifest: &Manifest) -> Result<Self> {
        let payload_bytes = serde_json::to_vec(manifest)?;
        let payload = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &payload_bytes);
        
        Ok(Self {
            payload,
            payload_type: "application/vnd.morse-kirby.manifest+json".to_string(),
            signatures: vec![],  // Filled by caller
        })
    }
}
```

**Deliverables:**
- [x] Add `DSSEEnvelope` struct
- [x] Add conversion from MKPE manifest
- [x] Add DSSE verification
- [x] Add DSSE tests

---

### 5.2 Multi-signature Support ✓ **LOW**

**Why:** Enterprise use cases need multiple approvers.

| Aspect | Detail |
|--------|--------|
| **Effort** | Medium (3-5 days) |
| **Severity** | Capability - enables enterprise |
| **Target** | Threshold signatures |

**Implementation:**

```rust
pub struct MultiSignature {
    pub threshold: usize,  // Minimum signatures required
    pub signatures: Vec<SignatureInfo>,
}

pub struct SignatureInfo {
    pub key_id: String,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
}

impl Manifest {
    pub fn verify_multisig(&self, multisig: &MultiSignature, trusted_keys: &[String]) -> Result<bool> {
        // 1. Check threshold
        if multisig.signatures.len() < multisig.threshold {
            return Err(MkpeError::VerificationFailed("Below threshold".into()));
        }
        
        // 2. Verify all signatures
        let mut valid = 0;
        for sig in &multisig.signatures {
            if trusted_keys.contains(&sig.key_id) {
                if verify_signature(&sig.key_id, self, &sig.signature)? {
                    valid += 1;
                }
            }
        }
        
        // 3. Check if enough valid signatures
        if valid >= multisig.threshold {
            Ok(true)
        } else {
            Err(MkpeError::VerificationFailed("Insufficient valid signatures".into()))
        }
    }
}
```

**Deliverables:**
- [x] Add `MultiSignature` struct
- [x] Add threshold verification
- [x] Add multi-sig tests

---

## Implementation Timeline

| Phase | Features | Duration | Risk |
|-------|----------|----------|------|
| **Phase 1** | Replay protection + Key rotation | 1 week | Low |
| **Phase 2** | Freshness + Manifest chaining | 1 week | Low |
| **Phase 3** | Audit log + Policy engine | 2 weeks | Medium |
| **Phase 4** | Build provenance | 1 week | Medium |
| **Phase 5** | Interoperability | 1 week | Low |

**Total estimated time:** 6-7 weeks

---

## Success Metrics

| Milestone | Metric |
|-----------|--------|
| Phase 1 complete | No replay attacks possible; key compromise recoverable |
| Phase 2 complete | Manifest chains verifiable; freshness guaranteed |
| Phase 3 complete | Audit trail available; policies enforceable |
| Phase 4 complete | Build provenance attestable |
| Phase 5 complete | Interoperable with Sigstore/in-toto |

---

## Decision Points

1. **Transparency log approach:** Should we implement embedded audit trail (simpler, local) or design for external integration (more complex, cross-org)?
2. **Policy language:** Should policies be JSON-based (simpler) or use a DSL like Rego (more powerful)?
3. **SLSA level target:** Which SLSA level should we target? Level 2 (easier) or Level 3 (requires build provenance infrastructure)?

---

## Next Steps

1. **Immediate:** Start Phase 1.1 (replay protection) - this addresses the most critical security gap
2. **This week:** Complete Phase 1.2 (key rotation) - required for all future trust features
3. **Next week:** Phase 2 (freshness + chaining) - enables verification of recent provenance


---

## Phase 6: Ownership Transfer Protocol (Digital Marketplace)

### 6.1 Transfer Manifest with Multi-Party Signing

- [x] `TransferManifest` struct with asset_id, from_key_id, to_key_id, marketplace_key_id
- [x] Deterministic transfer_id from SHA-256 of core fields
- [x] `TransferTerms` with price, currency, royalty_percentage, max_resale_count
- [x] Multi-party required_signers list with threshold-like execution
- [x] `sign()` auto-promotes status from Proposed to Executed when all required signatures collected
- [x] `verify_signatures()` validates each signature against trusted public keys
- [x] Canonical JSON payload excludes mutable status field to prevent signature invalidation on state change

### 6.2 Ownership Chain Validation

- [x] `OwnershipChain` struct with genesis anchoring and ordered transfer list
- [x] `append()` verifies: asset_id match, previous_manifest_id link, executed status, no revocation, cryptographic signature validity
- [x] `current_owner()` returns the `to_key_id` of the last valid transfer
- [x] `is_valid()` checks no revoked transfers and all executed statuses
- [x] `exceeds_resale_limit()` enforces max_resale_count from terms

### 6.3 Revocation

- [x] `RevocationEntry` with target_transfer_id, revoked_by, reason, signature
- [x] `RevocationEntry::new()` signs canonical revocation payload
- [x] `revocation.verify()` checks signature against revoker's public key
- [x] `OwnershipChain::revoke()` inserts revocation and invalidates chain validity

### 6.4 CLI Integration

- [x] `mkpe ownership transfer` creates transfer manifest with seller + optional marketplace signing
- [x] `mkpe ownership sign` adds a signature to an existing manifest and auto-promotes status
- [x] `mkpe ownership verify-chain` validates full ownership chain from genesis
- [x] `mkpe ownership revoke` creates a signed revocation entry
- [x] Deterministic key_id derivation from public key hash (self-sovereign identity without UUID dependency)
- [x] `public_key_to_key_id()` helper for consistent cross-party identification
- [x] `load_public_keys()` supports directory scanning and comma-separated file lists

### 6.5 Tests

- [x] Core unit tests: 13 ownership + 11 format-aware tests covering creation, signing, chain append, broken links, wrong asset, non-execution, revocation, resale limits, octet-stream, PNG, JSON adapters
- [x] CLI integration tests: 4 tests covering create-and-sign, verify-chain, revocation, marketplace escrow
- [x] All 255 core tests pass
- [x] All 13 CLI tests pass

### 6.6 Format-Aware DNA Embedding

- [x] `embed_format_aware(bytes, mime_type, secret)` — public API dispatching by MIME type
- [x] `embed_format_aware_with_payload(bytes, mime_type, secret, payload)` — content-specific tagging
- [x] `extract_format_aware(bytes, mime_type, secret)` — symmetric extraction
- [x] `OctetStreamAdapter` — backward-compatible raw byte-level LSB (reuses `dna.rs`)
- [x] `PngAdapter` — LSB in RGB(A) pixel channels with PNG-specific seed derivation; survives PNG re-encoding
- [x] `JsonAdapter` — hidden `_mkpe_dna` root key with base64-encoded DNA frame; survives pretty-print re-serialization

- [x] CLI `--mime-type` flag on `mkpe dna embed` and `mkpe dna extract`
- [x] 11 format-aware unit tests (roundtrip for all 3 formats, reencode survival, pretty-print survival, wrong secret, minimum size, missing key, unsupported MIME)

### 6.7 MkpeArchive Ownership Integration

- [x] `MkpeArchive` extended with optional `ownership: Option<OwnershipChain>`
- [x] Backward-compatible binary format: ownership-free bundles use plain `Vec<ProofBundle>` JSON; bundles with ownership use `ProofSection` wrapper object
- [x] `ProofSection` wrapper struct with `bundles` + optional `ownership` fields
- [x] `create_mkpe_bundle_with_ownership(dir, keypair, output, ownership)` public API
- [x] `ArchiveStats` exposes `has_ownership` and `transfer_count`
- [x] `MkpeArchive::verify()` rejects bundles with revoked or non-executed ownership chains
- [x] CLI `mkpe bundle --ownership <chain.json>` embeds ownership chain into `.mkpe`
- [x] CLI `mkpe verify --detailed` and `mkpe inspect` display ownership chain info
- [x] 3 core unit tests (roundtrip with valid chain, backward compat without ownership, revoked chain fails verify)
- [x] 1 CLI integration test (bundle with ownership roundtrip)

### 6.8 Hardware Key Support (TPM 2.0 + YubiKey)

- [x] `Signer` trait abstraction: `sign()`, `public_key()`, `key_id()`, `algorithm()`, `backend()`
- [x] `SigningKey` enum: `Software(KeyPair)`, `TpmSealed(TpmSealedKey)`, `YubiKeyHmac(YubiKeyHmacKey)`
- [x] `Algorithm` and `KeyBackend` enums for metadata and serialization
- [x] `TpmSealedKey`: Ed25519 private key stored in TPM NV memory (owner-read/owner-write)
- [x] `YubiKeyHmacKey`: Ed25519 seed derived from HMAC-SHA1 challenge-response via `challenge_response` crate
- [x] `generate_tpm_key()` and `generate_yubikey_key()` public APIs
- [x] `load_signing_key(path)` — tries `SigningKey` JSON first, falls back to legacy `KeyPair` format
- [x] `SigningKey::with_key_id()` for deterministic key-id override (ownership commands)
- [x] CLI `mkpe keygen --tpm` generates TPM-backed key as `mkpe_tpm.key.json`
- [x] CLI `mkpe keygen --yubikey` generates YubiKey-backed key as `mkpe_yubikey.key.json`
- [x] CLI `mkpe keygen` (default) still generates software keypair with backward-compatible file layout
- [x] All signing commands (`sign`, `bundle`, `attest`, `dsse`, `multisig`, `ownership`) accept hardware keys
- [x] DNA embed/extract commands gracefully error on hardware keys (private key not exportable)
- [x] Full core + CLI refactor: all `&KeyPair` parameters changed to `&dyn Signer`
- [x] Core backward compatibility: `KeyPair` implements `Signer`, all existing code continues to work
- [x] 5 new core unit tests (SigningKey software roundtrip, with_key_id, load fallback, TPM stub error, YubiKey stub error)