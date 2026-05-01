# 🎯 MKPE COMPLETE PROVENANCE ROADMAP
## From 35% → 100% Legal-Grade System

---

## 📊 CURRENT STATUS (v1.3.0)

**What's working:**
- ✅ SHA-256 hashing (100%)
- ✅ File metadata tracking (100%)
- ✅ Vault persistence (90%)
- ✅ Hash verification (100%)

**Overall completion: 35%**

**Missing for full Morse-Kirby provenance:**
- ❌ Ed25519 digital signatures
- ❌ Unique machine fingerprinting
- ❌ Complete provenance chain
- ❌ External verification
- ❌ Timestamping service
- ❌ C-DNA schema integration

---

## 🎯 PHASE 1: DIGITAL SIGNATURES (Days 1-3)
**Priority: CRITICAL**  
**Effort: 2-3 days**  
**Completion: 35% → 55%**

### **What it does:**
Makes your provenance **legally defensible** - cryptographic proof that YOU signed it.

### **Implementation Steps:**

#### **Day 1: Key Generation**
1. **Create Ed25519 key pair module:**
   ```rust
   // C:\MKPE\core\src\signatures.rs
   
   use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
   use rand::rngs::OsRng;
   
   pub struct SignatureManager {
       keypair: Keypair,
       public_key_path: PathBuf,
       private_key_path: PathBuf,
   }
   
   impl SignatureManager {
       pub fn generate_keypair() -> Keypair {
           let mut csprng = OsRng{};
           Keypair::generate(&mut csprng)
       }
       
       pub fn sign_message(&self, message: &[u8]) -> Signature {
           self.keypair.sign(message)
       }
       
       pub fn verify_signature(&self, message: &[u8], signature: &Signature) -> bool {
           self.keypair.verify(message, signature).is_ok()
       }
   }
   ```

2. **Store keys securely:**
   - Private key: Windows DPAPI encrypted in registry
   - Public key: Plain text in `C:\MKPE\keys\public.pem`
   - Backup: Encrypted key export to USB

3. **Add to Cargo.toml:**
   ```toml
   ed25519-dalek = "2.0"
   rand = "0.8"
   base64 = "0.21"
   ```

#### **Day 2: Sign Files on Vault Add**
1. **Update vault record structure:**
   ```rust
   #[derive(Serialize, Deserialize)]
   pub struct FileCreationRecord {
       pub file_path: String,
       pub file_type: String,
       pub created_at: DateTime<Utc>,
       pub created_by: String,
       pub machine_id: String,
       pub trust_level: TrustLevel,
       pub hash: String,
       pub provenance_chain: Vec<String>,
       pub verification_status: VerificationStatus,
       
       // NEW FIELDS:
       pub signature: String,              // Ed25519 signature
       pub public_key: String,             // Signer's public key
       pub signature_timestamp: String,    // When signature was created
   }
   ```

2. **Sign hash on file add:**
   ```rust
   pub fn add_file_creation(&mut self, file_path: String, created_by: String) {
       let hash = self.calculate_hash(&file_path);
       
       // NEW: Sign the hash
       let sig_manager = SignatureManager::load_or_create();
       let signature = sig_manager.sign_message(hash.as_bytes());
       let public_key = base64::encode(sig_manager.public_key().as_bytes());
       
       let record = FileCreationRecord {
           // ... existing fields ...
           signature: base64::encode(signature.to_bytes()),
           public_key,
           signature_timestamp: Utc::now().to_rfc3339(),
       };
       
       self.files.insert(file_path, record);
       self.save_vault();
   }
   ```

#### **Day 3: Verification UI**
1. **Add "Verify Signature" button to vault UI**
2. **Show signature status with icons:**
   - ✅ Signature valid
   - ❌ Signature invalid
   - 🔐 Digitally signed
3. **Export public key for external verification**

**Result:** Files are now cryptographically signed - YOU can prove YOU created them

---

## 🎯 PHASE 2: UNIQUE MACHINE ID (Day 4)
**Priority: HIGH**  
**Effort: 1 day**  
**Completion: 55% → 65%**

### **What it does:**
Track files across multiple computers with unique, persistent machine IDs.

### **Implementation Steps:**

1. **Generate unique machine ID:**
   ```rust
   use uuid::Uuid;
   use std::env;
   
   pub fn get_or_create_machine_id() -> String {
       // Check registry first
       if let Ok(id) = read_machine_id_from_registry() {
           return id;
       }
       
       // Generate new ID based on hardware
       let hostname = hostname::get().unwrap_or_default();
       let username = env::var("USERNAME").unwrap_or_default();
       let mac_address = get_primary_mac_address();
       
       let unique_id = format!(
           "MKPE-{}-{}-{}",
           hostname.to_string_lossy(),
           mac_address,
           Uuid::new_v4()
       );
       
       // Store in registry
       save_machine_id_to_registry(&unique_id);
       
       unique_id
   }
   
   fn get_primary_mac_address() -> String {
       // Use mac_address crate
       mac_address::get_mac_address()
           .unwrap()
           .map(|mac| mac.to_string())
           .unwrap_or_else(|| "00-00-00-00-00-00".to_string())
   }
   ```

2. **Windows registry storage:**
   ```rust
   use winreg::RegKey;
   use winreg::enums::*;
   
   fn save_machine_id_to_registry(machine_id: &str) {
       let hkcu = RegKey::predef(HKEY_CURRENT_USER);
       let key = hkcu.create_subkey("Software\\MKPE\\Identity").unwrap();
       key.set_value("MachineID", &machine_id).unwrap();
   }
   ```

3. **Add to Cargo.toml:**
   ```toml
   uuid = { version = "1.6", features = ["v4"] }
   mac_address = "1.1"
   winreg = "0.50"
   ```

**Result:** Each computer has unique, persistent ID - can track files across your 4 systems

---

## 🎯 PHASE 3: COMPLETE PROVENANCE CHAIN (Days 5-6)
**Priority: HIGH**  
**Effort: 2 days**  
**Completion: 65% → 75%**

### **What it does:**
Full chain of custody - track every event that happens to a file.

### **Implementation Steps:**

#### **Day 5: Provenance Event System**
1. **Define provenance events:**
   ```rust
   #[derive(Serialize, Deserialize, Clone)]
   pub struct ProvenanceEvent {
       pub event_type: EventType,
       pub timestamp: DateTime<Utc>,
       pub actor: String,              // username
       pub machine_id: String,
       pub location: String,           // file path
       pub details: HashMap<String, String>,
       pub signature: String,          // signed by actor
   }
   
   #[derive(Serialize, Deserialize, Clone)]
   pub enum EventType {
       Created,
       AddedToVault,
       Modified,
       Transferred,
       Verified,
       TrustElevated,
       Signed,
       Exported,
       Imported,
   }
   ```

2. **Append events to chain:**
   ```rust
   impl SecretsVault {
       pub fn add_provenance_event(
           &mut self,
           file_path: &str,
           event_type: EventType,
           details: HashMap<String, String>
       ) {
           let event = ProvenanceEvent {
               event_type,
               timestamp: Utc::now(),
               actor: get_current_user(),
               machine_id: get_machine_id(),
               location: file_path.to_string(),
               details,
               signature: sign_event_data(...),
           };
           
           if let Some(record) = self.files.get_mut(file_path) {
               record.provenance_chain.push(serde_json::to_string(&event).unwrap());
               self.save_vault();
           }
       }
   }
   ```

#### **Day 6: Chain Visualization**
1. **UI timeline view of provenance chain**
2. **Show each event with timestamp and actor**
3. **Visual chain diagram**
4. **Export chain to PDF/HTML**

**Result:** Complete audit trail - every action on file is recorded and signed

---

## 🎯 PHASE 4: EXTERNAL VERIFICATION (Days 7-10)
**Priority: CRITICAL**  
**Effort: 3-4 days**  
**Completion: 75% → 90%**

### **What it does:**
Anyone can verify your provenance proof WITHOUT needing MKPE installed.

### **Implementation Steps:**

#### **Day 7-8: Export Provenance Bundles**
1. **Create `.mkpe` file format:**
   ```json
   {
     "mkpe_version": "1.0",
     "bundle_id": "uuid",
     "created_at": "2025-01-08T...",
     "file_info": {
       "path": "C:\\...",
       "size": 1024,
       "hash": "sha256...",
       "signature": "ed25519..."
     },
     "provenance_chain": [...],
     "public_key": "base64...",
     "verification_instructions": "..."
   }
   ```

2. **Export button in UI:**
   - Right-click file in vault
   - "Export Provenance Proof"
   - Saves `.mkpe` bundle

3. **Bundle includes:**
   - File hash
   - All provenance events
   - Digital signatures
   - Public key for verification
   - Instructions for verification

#### **Day 9: Standalone Verifier**
1. **Create `mkpe_verify.exe`:**
   ```rust
   // Standalone verification tool
   fn main() {
       let bundle_path = env::args().nth(1).expect("Usage: mkpe_verify <bundle.mkpe>");
       let bundle = load_bundle(&bundle_path);
       
       println!("Verifying MKPE Provenance Bundle...");
       println!("File: {}", bundle.file_info.path);
       println!("Hash: {}", bundle.file_info.hash);
       
       // Verify signature
       if verify_signature(&bundle) {
           println!("✅ Signature VALID");
       } else {
           println!("❌ Signature INVALID");
       }
       
       // Verify chain integrity
       if verify_chain_integrity(&bundle) {
           println!("✅ Provenance chain intact");
       } else {
           println!("❌ Chain compromised");
       }
       
       // Show provenance timeline
       print_provenance_timeline(&bundle);
   }
   ```

2. **No dependencies on MKPE:**
   - Self-contained executable
   - Only needs `.mkpe` bundle file
   - Works on any Windows computer

#### **Day 10: Web Verification**
1. **Create HTML verification page:**
   ```html
   <!-- C:\MKPE\web\verify.html -->
   <!DOCTYPE html>
   <html>
   <head>
       <title>MKPE Verification</title>
   </head>
   <body>
       <h1>Verify MKPE Provenance</h1>
       <input type="file" id="bundleFile" accept=".mkpe">
       <button onclick="verifyBundle()">Verify</button>
       <div id="results"></div>
       
       <script>
           // JavaScript to parse and verify .mkpe files
           // Uses WebCrypto API for signature verification
       </script>
   </body>
   </html>
   ```

2. **WebAssembly verifier:**
   - Compile Rust verification code to WASM
   - Run in browser
   - No server needed

**Result:** Anyone can verify your provenance proofs independently

---

## 🎯 PHASE 5: TIMESTAMPING SERVICE (Days 11-13)
**Priority: HIGH**  
**Effort: 2-3 days**  
**Completion: 90% → 95%**

### **What it does:**
Third-party proof of WHEN file was created - can't be backdated.

### **Implementation Steps:**

#### **Day 11: RFC 3161 Integration**
1. **Add timestamping client:**
   ```rust
   use reqwest::Client;
   
   pub async fn get_rfc3161_timestamp(data: &[u8]) -> Result<Vec<u8>, Error> {
       let timestamp_authority = "http://timestamp.digicert.com";
       
       // Create timestamp request
       let request = create_timestamp_request(data);
       
       // Send to TSA
       let client = Client::new();
       let response = client
           .post(timestamp_authority)
           .header("Content-Type", "application/timestamp-query")
           .body(request)
           .send()
           .await?;
       
       // Parse timestamp response
       let timestamp_token = response.bytes().await?;
       Ok(timestamp_token.to_vec())
   }
   ```

2. **Free timestamp authorities:**
   - DigiCert: `http://timestamp.digicert.com`
   - Sectigo: `http://timestamp.sectigo.com`
   - GlobalSign: `http://timestamp.globalsign.com`

3. **Add to vault record:**
   ```rust
   pub struct FileCreationRecord {
       // ... existing fields ...
       pub rfc3161_timestamp: Option<Vec<u8>>,
       pub timestamp_authority: Option<String>,
   }
   ```

#### **Day 12-13: Timestamp Verification**
1. **Verify timestamp in UI**
2. **Show timestamp certificate chain**
3. **Export timestamp token**

**Result:** Provably created at specific time - can't claim "I created it earlier"

---

## 🎯 PHASE 6: C-DNA INTEGRATION (Days 14-21)
**Priority: MEDIUM (can be separate)**  
**Effort: 1-2 weeks**  
**Completion: 95% → 100%**

### **What it does:**
Full Morse-Kirby ecosystem - link to Calyx Brain, build provenance, complete attestation.

### **Implementation Steps:**

#### **Week 3: C-DNA Schema**
1. **Implement full c-DNA format:**
   ```rust
   #[derive(Serialize, Deserialize)]
   pub struct CDNAManifest {
       pub cdna_version: String,
       pub manifest_id: Uuid,
       pub created_at: DateTime<Utc>,
       
       pub attestation: Attestation,
       pub build_provenance: BuildProvenance,
       pub file_provenance: FileProvenance,
       pub verification: Verification,
   }
   
   pub struct Attestation {
       pub signature: String,
       pub signer_public_key: String,
       pub timestamp: Vec<u8>,
       pub chain_of_custody: Vec<ProvenanceEvent>,
   }
   
   pub struct BuildProvenance {
       pub source_hash: String,
       pub compiler_version: String,
       pub build_date: DateTime<Utc>,
       pub build_machine: String,
       pub dependencies: Vec<Dependency>,
   }
   ```

2. **Calyx Brain validation:**
   - Send c-DNA to Calyx for 0.35ms validation
   - Get semantic preservation score
   - Include in attestation

3. **Complete ecosystem:**
   - MKPE generates c-DNA
   - Calyx validates c-DNA
   - Aetherion can execute with provenance
   - Flow Editor can track workflow provenance

**Result:** Complete Morse-Kirby provenance ecosystem

---

## 📅 COMPLETE TIMELINE

### **Sprint 1: Signatures & Machine ID (Week 1)**
- Days 1-3: Ed25519 digital signatures
- Day 4: Unique machine fingerprinting
- **Milestone:** Cryptographically signed files

### **Sprint 2: Provenance & Verification (Week 2)**
- Days 5-6: Complete provenance chain
- Days 7-10: External verification
- **Milestone:** Third-party verifiable proofs

### **Sprint 3: Timestamping (Week 2-3)**
- Days 11-13: RFC 3161 timestamping
- **Milestone:** Provably timestamped files

### **Sprint 4: C-DNA Integration (Week 3-4)**
- Days 14-21: Full c-DNA schema
- **Milestone:** Complete Morse-Kirby ecosystem

**Total: 3-4 weeks to 100% completion**

---

## 💰 RESOURCES NEEDED

### **Development:**
- Your time: 3-4 weeks (you're fast!)
- Rust dependencies: Free (all open-source)
- Testing: Use your 4 systems

### **Services:**
- Timestamping: Free (public TSAs)
- Code signing cert: $200-400/year (optional)
- Domain for web verification: $12/year

### **Total cost: $0-400 (mostly free)**

---

## 🎯 PRIORITY ORDER

### **If you have 1 week:**
1. Digital signatures (Days 1-3)
2. Machine ID (Day 4)
3. Provenance chain (Days 5-6)
**Result:** 75% complete, legally useful

### **If you have 2 weeks:**
1. All of the above
2. External verification (Days 7-10)
3. Timestamping (Days 11-13)
**Result:** 95% complete, court-ready

### **If you have 3-4 weeks:**
1. All of the above
2. C-DNA integration (Days 14-21)
**Result:** 100% complete, full Morse-Kirby ecosystem

---

## 🚀 NEXT STEPS

### **RIGHT NOW:**
1. Review this roadmap
2. Decide on timeline (1, 2, or 3-4 weeks)
3. I'll start implementing Phase 1 (digital signatures)

### **TODAY:**
- Set up Ed25519 key generation
- Create signature manager module
- Update vault record structure

### **THIS WEEK:**
- Complete digital signatures
- Add unique machine ID
- Start provenance chain

### **NEXT WEEK:**
- External verification tool
- Timestamping integration
- Full testing across 4 systems

---

## 📊 FEATURE COMPARISON

| Feature | Current | After Phase 1 | After Phase 2 | After Phase 3 | Final |
|---------|---------|---------------|---------------|---------------|-------|
| File hashing | ✅ | ✅ | ✅ | ✅ | ✅ |
| Metadata tracking | ✅ | ✅ | ✅ | ✅ | ✅ |
| Digital signatures | ❌ | ✅ | ✅ | ✅ | ✅ |
| Unique machine ID | ❌ | ❌ | ✅ | ✅ | ✅ |
| Provenance chain | 🟡 | 🟡 | 🟡 | ✅ | ✅ |
| External verification | ❌ | ❌ | ❌ | ✅ | ✅ |
| Timestamping | ❌ | ❌ | ❌ | ✅ | ✅ |
| C-DNA integration | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Legal value** | Low | Medium | Medium | High | Maximum |
| **Court-ready** | ❌ | 🟡 | 🟡 | ✅ | ✅ |

---

## 🎉 BOTTOM LINE

**You need 3-4 weeks to go from 35% → 100%**

**Critical path (2 weeks for court-ready):**
1. Digital signatures (3 days)
2. Machine ID (1 day)
3. External verification (4 days)
4. Timestamping (3 days)

**After this, you'll have:**
- ✅ Cryptographically signed files
- ✅ Provably timestamped
- ✅ Third-party verifiable
- ✅ Court-admissible evidence
- ✅ Complete chain of custody
- ✅ Legal-grade provenance

**Ready to start?** I can begin implementing Phase 1 (digital signatures) right now!

---

*Document Version: 1.0*  
*Created: 2025-01-08*  
*Estimated completion: 3-4 weeks*  
*Target: 100% legal-grade provenance*
