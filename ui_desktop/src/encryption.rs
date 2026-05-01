//! MKPE File Encryption and Zip Encryption Module
//! 
//! Features:
//! - AES-256-GCM file encryption
//! - Password-protected ZIP with MKPE encryption
//! - Key derivation using PBKDF2
//! - Integrity verification

use eframe::egui;
use std::path::PathBuf;
use std::fs;
use serde::{Deserialize, Serialize};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, NewAead, generic_array::GenericArray}};
use pbkdf2::{pbkdf2_hmac};
use sha2::Sha256;
use rand::{Rng, rngs::OsRng};
use zip::{ZipWriter, CompressionMethod, write::FileOptions};
use std::io::{Write, Read};
use base64::{Engine as _, engine::general_purpose};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionRecord {
    pub original_path: String,
    pub encrypted_path: String,
    pub encryption_type: EncryptionType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub key_id: String,
    pub file_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EncryptionType {
    FileAES256,
    ZipMKPE,
}

#[derive(Debug, Clone)]
pub struct EncryptionManager {
    pub records: Vec<EncryptionRecord>,
    pub records_path: PathBuf,
    pub show_encryption: bool,
    pub selected_record: Option<String>,
}

impl EncryptionManager {
    pub fn new() -> Self {
        let records_path = PathBuf::from("C:\\MKPE\\secrets\\encryption_records.json");
        
        let mut manager = Self {
            records: Vec::new(),
            records_path,
            show_encryption: false,
            selected_record: None,
        };
        
        manager.load_records();
        manager
    }
    
    pub fn load_records(&mut self) {
        if let Ok(content) = std::fs::read_to_string(&self.records_path) {
            if let Ok(records) = serde_json::from_str::<Vec<EncryptionRecord>>(&content) {
                self.records = records;
            }
        }
    }
    
    pub fn save_records(&self) {
        if let Some(parent) = self.records_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        
        if let Ok(json) = serde_json::to_string_pretty(&self.records) {
            let _ = std::fs::write(&self.records_path, json);
        }
    }
    
    /// Encrypt a single file with AES-256-GCM
    pub fn encrypt_file(&mut self, file_path: &str, password: &str) -> Result<String, String> {
        let path = PathBuf::from(file_path);
        if !path.exists() {
            return Err("File does not exist".to_string());
        }
        
        // Generate key from password
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), b"mkpe_salt", 100000, &mut key);
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Read file content
        let file_content = fs::read(file_path)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        
        // Encrypt
        let cipher = Aes256Gcm::new(&Key::from_slice(&key));
        let ciphertext = cipher.encrypt(nonce, file_content.as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Create encrypted file path
        let encrypted_path = format!("{}.mkpe_encrypted", file_path);
        
        // Write encrypted file (nonce + ciphertext)
        let mut encrypted_data = Vec::new();
        encrypted_data.extend_from_slice(&nonce_bytes);
        encrypted_data.extend_from_slice(&ciphertext);
        
        fs::write(&encrypted_path, encrypted_data)
            .map_err(|e| format!("Failed to write encrypted file: {}", e))?;
        
        // Calculate hash
        let hash = sha2::Sha256::digest(&file_content);
        let file_hash = general_purpose::STANDARD.encode(&hash);
        
        // Create record
        let record = EncryptionRecord {
            original_path: file_path.to_string(),
            encrypted_path: encrypted_path.clone(),
            encryption_type: EncryptionType::FileAES256,
            created_at: chrono::Utc::now(),
            key_id: format!("aes256_{}", chrono::Utc::now().timestamp()),
            file_hash,
        };
        
        self.records.push(record);
        self.save_records();
        
        Ok(encrypted_path)
    }
    
    /// Create encrypted ZIP archive
    pub fn create_encrypted_zip(&mut self, folder_path: &str, output_path: &str, password: &str) -> Result<String, String> {
        let folder = PathBuf::from(folder_path);
        if !folder.exists() || !folder.is_dir() {
            return Err("Folder does not exist".to_string());
        }
        
        // Generate key from password
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), b"mkpe_zip_salt", 100000, &mut key);
        
        // Create ZIP file
        let file = fs::File::create(output_path)
            .map_err(|e| format!("Failed to create ZIP: {}", e))?;
        
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o755);
        
        // Add files to ZIP
        self.add_folder_to_zip(&mut zip, &folder, &folder, &options)?;
        
        zip.finish()
            .map_err(|e| format!("Failed to finish ZIP: {}", e))?;
        
        // Encrypt the ZIP file
        let encrypted_zip_path = format!("{}.mkpe_encrypted", output_path);
        self.encrypt_file(output_path, password)?;
        
        // Move encrypted version to final location
        fs::rename(format!("{}.mkpe_encrypted", output_path), &encrypted_zip_path)
            .map_err(|e| format!("Failed to move encrypted ZIP: {}", e))?;
        
        // Calculate hash
        let zip_content = fs::read(&encrypted_zip_path)
            .map_err(|e| format!("Failed to read encrypted ZIP: {}", e))?;
        let hash = sha2::Sha256::digest(&zip_content);
        let file_hash = general_purpose::STANDARD.encode(&hash);
        
        // Create record
        let record = EncryptionRecord {
            original_path: folder_path.to_string(),
            encrypted_path: encrypted_zip_path.clone(),
            encryption_type: EncryptionType::ZipMKPE,
            created_at: chrono::Utc::now(),
            key_id: format!("zip_{}", chrono::Utc::now().timestamp()),
            file_hash,
        };
        
        self.records.push(record);
        self.save_records();
        
        Ok(encrypted_zip_path)
    }
    
    fn add_folder_to_zip(
        &self,
        zip: &mut ZipWriter<fs::File>,
        folder: &PathBuf,
        base_path: &PathBuf,
        options: &FileOptions,
    ) -> Result<(), String> {
        for entry in fs::read_dir(folder)
            .map_err(|e| format!("Failed to read directory: {}", e))? {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            let path = entry.path();
            
            if path.is_dir() {
                self.add_folder_to_zip(zip, &path, base_path, options)?;
            } else {
                let relative_path = path.strip_prefix(base_path)
                    .map_err(|e| format!("Failed to get relative path: {}", e))?;
                
                zip.start_file(
                    relative_path.to_string_lossy(),
                    *options,
                ).map_err(|e| format!("Failed to start file in ZIP: {}", e))?;
                
                let mut file = fs::File::open(&path)
                    .map_err(|e| format!("Failed to open file: {}", e))?;
                
                std::io::copy(&mut file, zip)
                    .map_err(|e| format!("Failed to copy file to ZIP: {}", e))?;
            }
        }
        
        Ok(())
    }
    
    /// Decrypt a file
    pub fn decrypt_file(&self, encrypted_path: &str, password: &str) -> Result<Vec<u8>, String> {
        let path = PathBuf::from(encrypted_path);
        if !path.exists() {
            return Err("Encrypted file does not exist".to_string());
        }
        
        // Generate key from password
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), b"mkpe_salt", 100000, &mut key);
        
        // Read encrypted file
        let encrypted_data = fs::read(encrypted_path)
            .map_err(|e| format!("Failed to read encrypted file: {}", e))?;
        
        if encrypted_data.len() < 12 {
            return Err("Invalid encrypted file format".to_string());
        }
        
        // Extract nonce and ciphertext
        let nonce_bytes = &encrypted_data[0..12];
        let ciphertext = &encrypted_data[12..];
        let nonce = Nonce::from_slice(nonce_bytes);
        
        // Decrypt
        let cipher = Aes256Gcm::new(&Key::from_slice(&key));
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed - wrong password or corrupted file".to_string())?;
        
        Ok(plaintext)
    }
    
    /// Show encryption UI
    pub fn show_encryption_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("🔐 MKPE Encryption");
            
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Close").clicked() {
                    self.show_encryption = false;
                }
            });
        });
        
        ui.separator();
        
        // Encryption controls
        ui.horizontal(|ui| {
            if ui.button("🔒 Encrypt File").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .pick_file() {
                    
                    // For demo, use a simple password dialog
                    // In real implementation, use a proper password dialog
                    let password = "demo_password"; // This should be user input
                    
                    match self.encrypt_file(&path.to_string_lossy(), password) {
                        Ok(encrypted_path) => {
                            ui.label(format!("✅ File encrypted: {}", encrypted_path));
                        }
                        Err(e) => {
                            ui.label(format!("❌ Encryption failed: {}", e));
                        }
                    }
                }
            }
            
            if ui.button("📁 Encrypt Folder (ZIP)").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .pick_folder() {
                    
                    let output_path = format!("{}.mkpe_encrypted.zip", path.to_string_lossy());
                    let password = "demo_password"; // This should be user input
                    
                    match self.create_encrypted_zip(&path.to_string_lossy(), &output_path, password) {
                        Ok(encrypted_path) => {
                            ui.label(format!("✅ Folder encrypted: {}", encrypted_path));
                        }
                        Err(e) => {
                            ui.label(format!("❌ Encryption failed: {}", e));
                        }
                    }
                }
            }
        });
        
        ui.separator();
        
        // Show encryption records
        ui.heading("Encrypted Files");
        
        egui::ScrollArea::vertical().show(ui, |ui| {
            for record in &self.records {
                ui.horizontal(|ui| {
                    let icon = match record.encryption_type {
                        EncryptionType::FileAES256 => "🔒",
                        EncryptionType::ZipMKPE => "📁",
                    };
                    
                    ui.label(icon);
                    ui.label(&record.original_path);
                    
                    if ui.button("Decrypt").clicked() {
                        // Decryption logic would go here
                        ui.label("Decryption dialog would appear here");
                    }
                });
                
                ui.label(format!("   Created: {}", record.created_at.format("%Y-%m-%d %H:%M:%S")));
                ui.label(format!("   Hash: {}...", &record.file_hash[..16]));
                ui.add_space(10.0);
            }
        });
    }
}
