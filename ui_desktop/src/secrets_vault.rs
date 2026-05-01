//! MKPE Secrets Vault - File Creation Tracking and Trust Management
use eframe::egui;
use std::collections::HashMap;
use std::path::PathBuf;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use morse_kirby_core::{crypto, proof};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    
    // Cryptographic provenance
    pub signature: Option<String>,
    pub public_key: Option<String>,
    pub signature_timestamp: Option<String>,
    pub proof_bundle_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustLevel {
    Untrusted,
    Basic,
    Trusted,
    HighTrust,
    Verified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerificationStatus {
    Pending,
    Verified,
    Failed,
    Warning,
}

#[derive(Debug, Clone)]
pub struct SecretsVault {
    pub files: HashMap<String, FileCreationRecord>,
    pub vault_path: PathBuf,
    pub show_vault: bool,
    pub selected_file: Option<String>,
    keypair: Option<crypto::KeyPair>,
}

impl SecretsVault {
    pub fn new() -> Self {
        let vault_path = PathBuf::from("C:\\MKPE\\secrets\\vault.json");
        
        // Load or generate keypair
        let keypair = Self::load_or_generate_keypair();
        
        Self {
            files: HashMap::new(),
            vault_path,
            show_vault: false,
            selected_file: None,
            keypair: Some(keypair),
        }
    }
    
    fn load_or_generate_keypair() -> crypto::KeyPair {
        let key_path = PathBuf::from("C:\\MKPE\\secrets\\keypair.json");
        
        if key_path.exists() {
            if let Ok(key_data) = std::fs::read_to_string(&key_path) {
                if let Ok(keypair) = serde_json::from_str(&key_data) {
                    return keypair;
                }
            }
        }
        
        // Generate new keypair
        let keypair = crypto::generate_keypair();
        
        // Save keypair
        if let Some(parent) = key_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(key_json) = serde_json::to_string_pretty(&keypair) {
            let _ = std::fs::write(&key_path, key_json);
        }
        
        keypair
    }

    pub fn load_vault(&mut self) {
        if let Ok(content) = std::fs::read_to_string(&self.vault_path) {
            if let Ok(records) = serde_json::from_str::<Vec<FileCreationRecord>>(&content) {
                self.files.clear();
                for record in records {
                    self.files.insert(record.file_path.clone(), record);
                }
            }
        }
    }

    pub fn save_vault(&self) {
        if let Some(parent) = self.vault_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        
        let records: Vec<&FileCreationRecord> = self.files.values().collect();
        if let Ok(json) = serde_json::to_string_pretty(&records) {
            let _ = std::fs::write(&self.vault_path, json);
        }
    }

    pub fn add_file_creation(&mut self, file_path: String, created_by: String) {
        let file_type = self.detect_file_type(&file_path);
        let hash = self.calculate_hash(&file_path);
        let machine_id = self.get_machine_id();
        let timestamp = Utc::now();
        
        // Create signature with Ed25519
        let (signature, public_key, proof_bundle_id) = if let Some(ref keypair) = self.keypair {
            let proof_data = format!("{}:{}:{}", file_path, hash, timestamp.to_rfc3339());
            let sig = keypair.sign(proof_data.as_bytes()).ok();
            let pubkey = Some(keypair.public_key.clone());
            let bundle_id = Some(uuid::Uuid::new_v4().to_string());
            (sig, pubkey, bundle_id)
        } else {
            (None, None, None)
        };
        
        let trust_level = if signature.is_some() {
            TrustLevel::Verified  // Cryptographically signed = Verified trust
        } else {
            TrustLevel::Basic
        };
        
        let record = FileCreationRecord {
            file_path: file_path.clone(),
            file_type,
            created_at: timestamp,
            created_by,
            machine_id,
            trust_level,
            hash,
            provenance_chain: vec!["MKPE_CREATION".to_string()],
            verification_status: VerificationStatus::Verified,
            signature,
            public_key,
            signature_timestamp: Some(timestamp.to_rfc3339()),
            proof_bundle_id,
        };

        self.files.insert(file_path, record);
        self.save_vault();
    }

    fn detect_file_type(&self, file_path: &str) -> String {
        if let Some(extension) = std::path::Path::new(file_path).extension() {
            match extension.to_str().unwrap_or("").to_lowercase().as_str() {
                "dcx" => "Document Container".to_string(),
                "pdf" => "PDF Document".to_string(),
                "rs" => "Rust Source Code".to_string(),
                "exe" => "Executable".to_string(),
                "dll" => "Dynamic Library".to_string(),
                "json" => "JSON Data".to_string(),
                "mkpe" => "MKPE Provenance Bundle".to_string(),
                _ => format!("Unknown ({})", extension.to_str().unwrap_or("unknown")),
            }
        } else {
            "Unknown".to_string()
        }
    }

    fn calculate_hash(&self, file_path: &str) -> String {
        if let Ok(content) = std::fs::read(file_path) {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&content);
            format!("{:x}", hasher.finalize())
        } else {
            "file_not_found".to_string()
        }
    }

    fn get_machine_id(&self) -> String {
        // Simplified machine ID - in production, use proper machine identification
        "MACHINE_001".to_string()
    }

    pub fn show_vault_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔐 MKPE Secrets Vault");
        ui.separator();

        // File creation summary
        let total_files = self.files.len();
        let verified_files = self.files.values()
            .filter(|f| f.verification_status == VerificationStatus::Verified)
            .count();
        let high_trust_files = self.files.values()
            .filter(|f| matches!(f.trust_level, TrustLevel::HighTrust | TrustLevel::Verified))
            .count();

        ui.horizontal(|ui| {
            ui.label(format!("📁 Total Files: {}", total_files));
            ui.label(format!("✅ Verified: {}", verified_files));
            ui.label(format!("🔒 High Trust: {}", high_trust_files));
        });

        ui.separator();

        // File list
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (file_path, record) in &self.files {
                let is_selected = self.selected_file.as_ref() == Some(file_path);
                
                let trust_icon = match record.trust_level {
                    TrustLevel::Verified => "🔒",
                    TrustLevel::HighTrust => "🛡️",
                    TrustLevel::Trusted => "✅",
                    TrustLevel::Basic => "⚠️",
                    TrustLevel::Untrusted => "❌",
                };

                let status_icon = match record.verification_status {
                    VerificationStatus::Verified => "✅",
                    VerificationStatus::Pending => "⏳",
                    VerificationStatus::Failed => "❌",
                    VerificationStatus::Warning => "⚠️",
                };

                let row_color = if is_selected {
                    egui::Color32::from_rgb(50, 50, 70)
                } else {
                    egui::Color32::TRANSPARENT
                };

                ui.horizontal(|ui| {
                    ui.set_min_height(30.0);
                    
                    // Background color
                    ui.painter().rect_filled(
                        ui.available_rect_before_wrap(),
                        2.0,
                        row_color,
                    );

                    if ui.selectable_label(is_selected, format!(
                        "{} {} {} {}",
                        trust_icon,
                        status_icon,
                        record.file_type,
                        std::path::Path::new(file_path).file_name()
                            .unwrap_or_default()
                            .to_str()
                            .unwrap_or("Unknown")
                    )).clicked() {
                        self.selected_file = Some(file_path.clone());
                    }
                });
            }
        });

        ui.separator();

        // File details
        if let Some(selected_path) = &self.selected_file {
            if let Some(record) = self.files.get(selected_path) {
                ui.group(|ui| {
                    ui.heading("📋 File Details");
                    
                    ui.horizontal(|ui| {
                        ui.label("📁 Path:");
                        ui.label(selected_path);
                    });
                    
                    ui.horizontal(|ui| {
                        ui.label("📄 Type:");
                        ui.label(&record.file_type);
                    });
                    
                    ui.horizontal(|ui| {
                        ui.label("👤 Created by:");
                        ui.label(&record.created_by);
                    });
                    
                    ui.horizontal(|ui| {
                        ui.label("🖥️ Machine:");
                        ui.label(&record.machine_id);
                    });
                    
                    ui.horizontal(|ui| {
                        ui.label("⏰ Created:");
                        ui.label(record.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string());
                    });
                    
                    ui.horizontal(|ui| {
                        ui.label("🔐 Trust Level:");
                        let trust_text = match record.trust_level {
                            TrustLevel::Verified => "🔒 Verified (Cryptographically Signed)",
                            TrustLevel::HighTrust => "🛡️ High Trust",
                            TrustLevel::Trusted => "✅ Trusted",
                            TrustLevel::Basic => "⚠️ Basic",
                            TrustLevel::Untrusted => "❌ Untrusted",
                        };
                        let color = if record.trust_level == TrustLevel::Verified {
                            egui::Color32::from_rgb(0, 255, 200)  // Neon cyan for verified
                        } else {
                            egui::Color32::WHITE
                        };
                        ui.colored_label(color, trust_text);
                    });
                    
                    // Show signature info if present
                    if let Some(ref sig) = record.signature {
                        ui.horizontal(|ui| {
                            ui.label("✍️ Signature:");
                            ui.label(format!("{}...", &sig[..16.min(sig.len())]));
                        });
                    }
                    
                    if let Some(ref bundle_id) = record.proof_bundle_id {
                        ui.horizontal(|ui| {
                            ui.label("📦 Proof Bundle:");
                            ui.label(format!("{}...", &bundle_id[..8]));
                        });
                    }
                    
                    ui.horizontal(|ui| {
                        ui.label("🔍 Hash:");
                        ui.label(format!("{}...", &record.hash[..16]));
                    });
                });
            }
        }
    }
}
