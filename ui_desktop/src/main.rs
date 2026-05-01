//! MKPE Desktop - Sleek Protection Interface
// #![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::collections::VecDeque;
use std::path::PathBuf;

mod secrets_vault;
use secrets_vault::SecretsVault;

// mod encryption;
// use encryption::EncryptionManager;

mod crash_handler;

#[derive(serde::Deserialize, serde::Serialize, Clone)]
struct LogEntry {
    timestamp_utc: String,
    action: String,
    status: String,
    file: String,
    details: String,
}

struct MkpeApp {
    // Core state
    service_running: bool,
    files_protected: usize,
    last_protection_scan: String,
    
    // Protected folders
    protected_folders: Vec<String>,
    new_folder_input: String,
    show_add_dialog: bool,
    
    // Activity
    recent_activity: VecDeque<String>,
    threat_log: Vec<String>,
    
    // UI state
    last_refresh: std::time::Instant,
    config_path: PathBuf,
    selected_tab: Tab,
    protection_status: ProtectionStatus,
    user_manual_override: bool,
    
    // Secrets vault
    secrets_vault: SecretsVault,
}

#[derive(PartialEq)]
enum Tab {
    Protection,
    Folders,
    Activity,
    Vault,
}

#[derive(PartialEq)]
enum ProtectionStatus {
    Secure,
    Scanning,
    ThreatDetected,
    Offline,
}

impl Default for MkpeApp {
    fn default() -> Self {
        let config_path = PathBuf::from("C:\\ProgramData\\MKPE\\config.json");
        let mut app = Self {
            service_running: false,
            files_protected: 0,
            last_protection_scan: "Never".to_string(),
            protected_folders: Vec::new(),
            new_folder_input: String::new(),
            show_add_dialog: false,
            recent_activity: VecDeque::with_capacity(100),
            threat_log: Vec::new(),
            last_refresh: std::time::Instant::now(),
            config_path,
            selected_tab: Tab::Protection,
            protection_status: ProtectionStatus::Offline,
            user_manual_override: false,
            secrets_vault: SecretsVault::new(),
        };
        app.load_config();
        app.refresh_logs();
        app.secrets_vault.load_vault();
        app
    }
}

impl MkpeApp {
    fn load_config(&mut self) {
        if let Ok(content) = std::fs::read_to_string(&self.config_path) {
            if let Ok(config) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(paths) = config["service_config"]["watch_paths"].as_array() {
                    self.protected_folders = paths
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                }
            }
        }
    }
    
    fn save_config(&self) {
        // Create config directory if it doesn't exist
        if let Some(parent) = self.config_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        
        // Load existing config or create new one
        let mut config = if let Ok(content) = std::fs::read_to_string(&self.config_path) {
            serde_json::from_str::<serde_json::Value>(&content).unwrap_or(serde_json::json!({}))
        } else {
            serde_json::json!({})
        };
        
        // Ensure service_config exists
        if !config["service_config"].is_object() {
            config["service_config"] = serde_json::json!({});
        }
        
        // Update protected folders
        config["service_config"]["watch_paths"] = serde_json::json!(self.protected_folders);
        
        // Save config
        if let Ok(updated) = serde_json::to_string_pretty(&config) {
            let _ = std::fs::write(&self.config_path, updated);
            self.restart_service();
        }
    }
    
    fn restart_service(&self) {
        let _ = std::process::Command::new("taskkill").args(&["/F", "/IM", "mkpe_service.exe"]).output();
        std::thread::sleep(std::time::Duration::from_millis(500));
        // We'll trust the path is in the current directory for dev/demo purposes, 
        // or a known installed location. For this run, we won't hardcode the path effectively.
        let _ = std::process::Command::new("mkpe_service.exe").spawn();
    }
    
    fn refresh_logs(&mut self) {
        let log_dir = PathBuf::from("C:\\ProgramData\\MKPE\\logs");
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let log_file = log_dir.join(format!("{}.jsonl", today));

        self.recent_activity.clear();
        self.threat_log.clear();

        if log_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&log_file) {
                for line in content.lines() {
                    if let Ok(entry) = serde_json::from_str::<LogEntry>(line) {
                        let time = entry.timestamp_utc.split('T').nth(1).unwrap_or("").split('.').next().unwrap_or("");
                        
                        match entry.action.as_str() {
                            "scan_completed" => {
                                self.last_protection_scan = time.to_string();
                                if let Some(num_str) = entry.details.split("Checked: ").nth(1) {
                                    if let Some(num) = num_str.split(',').next() {
                                        self.files_protected = num.trim().parse().unwrap_or(0);
                                    }
                                }
                                // Only update status if user hasn't manually overridden it
                                if !self.user_manual_override {
                                    if entry.details.contains("Errors: 0") {
                                        self.protection_status = ProtectionStatus::Secure;
                                    } else {
                                        self.protection_status = ProtectionStatus::ThreatDetected;
                                    }
                                }
                            },
                            "scan_started" => {
                                if !self.user_manual_override {
                                    self.protection_status = ProtectionStatus::Scanning;
                                }
                                let msg = format!("🔄 Protection scan initiated at {}", time);
                                self.recent_activity.push_front(msg);
                            },
                            "verify" if entry.status == "ERROR" => {
                                let error_msg = format!("⚠️ Verification error: {}", entry.details);
                                self.threat_log.push(error_msg.clone());
                                self.recent_activity.push_front(error_msg);
                            },
                            _ => {
                                let msg = format!("✅ {} - {}", entry.action, entry.details);
                                self.recent_activity.push_front(msg);
                            }
                        }
                    }
                }
                self.service_running = true;
            }
        }
        
        if self.recent_activity.len() > 50 {
            self.recent_activity.truncate(50);
        }
    }
    
    fn show_vault(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(20.0);
            ui.vertical(|ui| {
                ui.add_space(10.0);
                ui.label(egui::RichText::new("Secrets Vault").size(20.0));
                ui.label(egui::RichText::new("Track file creation and trust levels").size(12.0).color(egui::Color32::GRAY));
                
                ui.add_space(20.0);
                
                // BIG CRISP MKPE LOGO with NEON RING - RIGHT HERE!
                let (glow_color, status_text) = match self.protection_status {
                    ProtectionStatus::Secure => (egui::Color32::from_rgb(0, 200, 255), "PROTECTED"),  // Neon blue
                    ProtectionStatus::Scanning => (egui::Color32::from_rgb(255, 200, 100), "SCANNING"),
                    ProtectionStatus::ThreatDetected => (egui::Color32::from_rgb(255, 50, 50), "OFFLINE"),  // Red
                    ProtectionStatus::Offline => (egui::Color32::from_rgb(255, 50, 50), "OFFLINE"),  // Neon red
                };
                
                ui.horizontal(|ui| {
                    ui.vertical_centered(|ui| {
                        // BIG MKPE LOGO with NEON RING
                        let (rect, _) = ui.allocate_exact_size(egui::vec2(120.0, 120.0), egui::Sense::hover());
                        let painter = ui.painter();
                        let center = rect.center();
                        
                        // BIG neon glow effect
                        for i in (0..6).rev() {
                            let glow_radius = 50.0 + (i as f32 * 8.0);
                            let alpha = 50 - (i * 6);
                            let mut color_with_alpha = glow_color;
                            color_with_alpha[3] = alpha as u8;
                            painter.circle_filled(center, glow_radius, color_with_alpha);
                        }
                        
                        // BIG main circle
                        painter.circle_filled(center, 45.0, glow_color);
                        
                        // BIG MKPE TEXT LOGO (simplified to avoid API issues)
                        painter.text(
                            center,
                            egui::Align2::CENTER_CENTER,
                            "MKPE v2.0",
                            egui::FontId::proportional(20.0),
                            egui::Color32::from_rgb(10, 10, 15),
                        );
                        
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new(status_text).size(14.0).color(glow_color).strong());
                    });
                    
                    ui.add_space(30.0);
                    
                    // Files Protected stats next to logo
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new("Files Protected").size(16.0).strong());
                        ui.add_space(5.0);
                        ui.label(egui::RichText::new(self.files_protected.to_string()).size(48.0).color(egui::Color32::from_rgb(100, 200, 255)));
                        ui.label(egui::RichText::new("Active Monitoring").size(12.0).color(egui::Color32::GRAY));
                    });
                });
                
                ui.add_space(20.0);
                
                // Add file creation button
                if ui.button(egui::RichText::new("➕ Add File to Vault").size(14.0)).clicked() {
                    // Open file picker
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Select file to add to vault")
                        .pick_file()
                    {
                        if let Some(path_str) = path.to_str() {
                            let username = std::env::var("USERNAME")
                                .or_else(|_| std::env::var("USER"))
                                .unwrap_or_else(|_| "Unknown".to_string());
                            
                            self.secrets_vault.add_file_creation(
                                path_str.to_string(),
                                username
                            );
                        }
                    }
                }
                
                ui.add_space(20.0);
                
                // Show vault UI
                self.secrets_vault.show_vault_ui(ui);
            });
        });
    }
}

impl eframe::App for MkpeApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Auto-refresh every 3 seconds
        if self.last_refresh.elapsed().as_secs() >= 3 {
            self.refresh_logs();
            self.last_refresh = std::time::Instant::now();
            ctx.request_repaint();
        }
        
        // Sleek dark theme
        let mut style = (*ctx.style()).clone();
        style.visuals = egui::Visuals::dark();
        style.visuals.window_rounding = egui::Rounding::same(0.0);
        style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(18, 18, 23);
        style.visuals.extreme_bg_color = egui::Color32::from_rgb(12, 12, 16);
        style.visuals.faint_bg_color = egui::Color32::from_rgb(25, 25, 30);
        ctx.set_style(style);
        
        // Main layout
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                // Sleek icon sidebar
                egui::SidePanel::left("icon_sidebar")
                    .exact_width(60.0)
                    .resizable(false)
                    .show_inside(ui, |ui| {
                        ui.add_space(20.0);
                        
                        // Clean MKPE logo with NEON GLOW - NO THREAT ICONS
                        let (glow_color, status_text) = match self.protection_status {
                            ProtectionStatus::Secure => (egui::Color32::from_rgb(0, 200, 255), "PROTECTED"),  // Neon blue
                            ProtectionStatus::Scanning => (egui::Color32::from_rgb(255, 200, 100), "SCANNING"),
                            ProtectionStatus::ThreatDetected => (egui::Color32::from_rgb(255, 50, 50), "OFFLINE"),  // Red but no threat icon
                            ProtectionStatus::Offline => (egui::Color32::from_rgb(255, 50, 50), "OFFLINE"),  // Neon red
                        };
                        
                        ui.vertical_centered(|ui| {
                            // Load and display YOUR actual MKPE icon with neon glow
                            let (rect, _) = ui.allocate_exact_size(egui::vec2(50.0, 50.0), egui::Sense::hover());
                            let painter = ui.painter();
                            let center = rect.center();
                            
                            // Neon glow effect behind YOUR icon
                            for i in (0..4).rev() {
                                let glow_radius = 20.0 + (i as f32 * 4.0);
                                let alpha = 40 - (i * 8);
                                let mut color_with_alpha = glow_color;
                                color_with_alpha[3] = alpha as u8;
                                painter.circle_filled(center, glow_radius, color_with_alpha);
                            }
                            
                            // MKPE TEXT LOGO (simplified to avoid API issues)
                            painter.text(
                                center,
                                egui::Align2::CENTER_CENTER,
                                "MKPE",
                                egui::FontId::proportional(12.0),
                                egui::Color32::from_rgb(10, 10, 15),
                            );
                            
                            ui.label(egui::RichText::new(status_text).size(8.0).color(glow_color));
                        });
                        
                        ui.add_space(30.0);
                        
                        // Navigation icons
                        let tab_icon = |ui: &mut egui::Ui, tab: Tab, icon: &str, current: &Tab| {
                            let is_selected = tab == *current;
                            let color = if is_selected {
                                egui::Color32::from_rgb(100, 200, 255)
                            } else {
                                egui::Color32::from_gray(100)
                            };
                            
                            let button = egui::Button::new(egui::RichText::new(icon).size(20.0).color(color))
                                .fill(if is_selected { egui::Color32::from_rgb(30, 30, 40) } else { egui::Color32::TRANSPARENT })
                                .min_size(egui::vec2(40.0, 40.0));
                            
                            ui.add(button).clicked()
                        };
                        
                        if tab_icon(ui, Tab::Protection, "🏠", &self.selected_tab) {
                            self.selected_tab = Tab::Protection;
                        }
                        ui.add_space(10.0);
                        
                        if tab_icon(ui, Tab::Folders, "📁", &self.selected_tab) {
                            self.selected_tab = Tab::Folders;
                        }
                        ui.add_space(10.0);
                        
                        if tab_icon(ui, Tab::Activity, "📊", &self.selected_tab) {
                            self.selected_tab = Tab::Activity;
                        }
                        
                        ui.add_space(10.0);
                        
                        if tab_icon(ui, Tab::Vault, "🔐", &self.selected_tab) {
                            self.selected_tab = Tab::Vault;
                        }
                    });
                
                // Main content area
                egui::CentralPanel::default().show_inside(ui, |ui| {
                    ui.add_space(20.0);
                    
                    match self.selected_tab {
                        Tab::Protection => self.show_protection_dashboard(ui),
                        Tab::Folders => self.show_folders(ui),
                        Tab::Activity => self.show_activity(ui),
                        Tab::Vault => self.show_vault(ui),
                    }
                });
            });
        });
    }
}

impl MkpeApp {
    fn show_protection_dashboard(&mut self, ui: &mut egui::Ui) {
        // Main protection status
        ui.horizontal(|ui| {
            ui.add_space(20.0);
            ui.vertical(|ui| {
                ui.add_space(10.0);
                
                // Clean status message - NO THREAT LANGUAGE
                let (status_msg, status_color, sub_msg) = match self.protection_status {
                    ProtectionStatus::Secure => (
                        "Your Work is Protected",
                        egui::Color32::from_rgb(100, 255, 150),
                        "All files verified and secure"
                    ),
                    ProtectionStatus::Scanning => (
                        "System Monitoring Active",
                        egui::Color32::from_rgb(255, 200, 100),
                        "Tracking file changes..."
                    ),
                    ProtectionStatus::ThreatDetected => (
                        "System Offline",
                        egui::Color32::from_rgb(200, 200, 200),
                        "Protection service needs restart"
                    ),
                    ProtectionStatus::Offline => (
                        "Protection Offline",
                        egui::Color32::from_rgb(200, 200, 200),
                        "Start the protection service"
                    ),
                };
                
                ui.label(egui::RichText::new(status_msg).size(28.0).color(status_color).strong());
                ui.label(egui::RichText::new(sub_msg).size(14.0).color(egui::Color32::GRAY));
                
                ui.add_space(20.0);
                
                // BIG CRISP MKPE LOGO with NEON RING - RIGHT IN MAIN DASHBOARD!
                let (glow_color, status_text) = match self.protection_status {
                    ProtectionStatus::Secure => (egui::Color32::from_rgb(0, 200, 255), "PROTECTED"),  // Neon blue
                    ProtectionStatus::Scanning => (egui::Color32::from_rgb(255, 200, 100), "SCANNING"),
                    ProtectionStatus::ThreatDetected => (egui::Color32::from_rgb(255, 50, 50), "OFFLINE"),  // Red
                    ProtectionStatus::Offline => (egui::Color32::from_rgb(255, 50, 50), "OFFLINE"),  // Neon red
                };
                
                // BIG INTERACTIVE NEON LOGO - CENTERED AND BIGGER
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    
                    // BIG interactive logo area - 200x200 pixels
                    let (rect, response) = ui.allocate_exact_size(egui::vec2(200.0, 200.0), egui::Sense::click());
                    let painter = ui.painter();
                    let center = rect.center();
                    
                    // Handle click to toggle protection
                    if response.clicked() {
                        self.protection_status = match self.protection_status {
                            ProtectionStatus::Offline => ProtectionStatus::Secure,
                            ProtectionStatus::Secure => ProtectionStatus::Offline,
                            _ => ProtectionStatus::Secure,
                        };
                        self.user_manual_override = true; // Prevent auto-revert
                    }
                    
                    // BIG neon glow effect - just the ring
                    for i in (0..4).rev() {
                        let glow_radius = 80.0 + (i as f32 * 10.0);
                        let alpha = 40 - (i * 8);
                        let mut color_with_alpha = glow_color;
                        color_with_alpha[3] = alpha as u8;
                        painter.circle_stroke(center, glow_radius, egui::Stroke::new(8.0, color_with_alpha));
                    }
                    
                    // Main ring
                    painter.circle_stroke(center, 80.0, egui::Stroke::new(6.0, glow_color));
                    
                    // YOUR LOGO TEXT (will add image later once API is fixed)
                    painter.text(
                        center,
                        egui::Align2::CENTER_CENTER,
                        "MKPE",
                        egui::FontId::proportional(28.0),
                        egui::Color32::WHITE,
                    );
                    
                    ui.add_space(15.0);
                    ui.label(egui::RichText::new(status_text).size(16.0).color(glow_color).strong());
                    ui.label(egui::RichText::new("Click to toggle protection").size(12.0).color(egui::Color32::GRAY));
                });
                
                ui.add_space(30.0);
                
                // Files Protected stats below logo
                ui.horizontal_centered(|ui| {
                    ui.label(egui::RichText::new("Files Protected").size(16.0).strong());
                    ui.add_space(10.0);
                    ui.label(egui::RichText::new(self.files_protected.to_string()).size(32.0).color(egui::Color32::from_rgb(100, 200, 255)));
                    ui.add_space(10.0);
                    ui.label(egui::RichText::new("Active Monitoring").size(12.0).color(egui::Color32::GRAY));
                });
                
                ui.add_space(20.0);
                
                // Protection stats in beautiful cards
                ui.horizontal(|ui| {
                    // Files Protected
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(25, 35, 45))
                        .rounding(egui::Rounding::same(12.0))
                        .inner_margin(egui::Margin::same(20.0))
                        .show(ui, |ui| {
                            ui.set_min_width(180.0);
                            ui.vertical_centered(|ui| {
                                ui.label(egui::RichText::new("📁").size(24.0));
                                ui.label(egui::RichText::new("FILES PROTECTED").size(10.0).color(egui::Color32::GRAY));
                                ui.add_space(8.0);
                                ui.label(egui::RichText::new(self.files_protected.to_string()).size(32.0).color(egui::Color32::from_rgb(100, 255, 150)));
                            });
                        });
                    
                    ui.add_space(15.0);
                    
                    // Last Scan
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(25, 35, 45))
                        .rounding(egui::Rounding::same(12.0))
                        .inner_margin(egui::Margin::same(20.0))
                        .show(ui, |ui| {
                            ui.set_min_width(180.0);
                            ui.vertical_centered(|ui| {
                                ui.label(egui::RichText::new("🕐").size(24.0));
                                ui.label(egui::RichText::new("LAST SCAN").size(10.0).color(egui::Color32::GRAY));
                                ui.add_space(8.0);
                                ui.label(egui::RichText::new(&self.last_protection_scan).size(18.0).color(egui::Color32::WHITE));
                            });
                        });
                });
                
                ui.add_space(30.0);
                
                // Protected Folders Summary
                ui.label(egui::RichText::new("Protected Workspaces").size(16.0).color(egui::Color32::WHITE));
                ui.add_space(10.0);
                
                if self.protected_folders.is_empty() {
                    ui.colored_label(egui::Color32::YELLOW, "⚠️ No workspaces protected yet");
                    ui.add_space(5.0);
                    ui.label(egui::RichText::new("Add folders to protect your creative work").size(12.0).color(egui::Color32::GRAY));
                } else {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(25, 25, 30))
                        .rounding(egui::Rounding::same(8.0))
                        .inner_margin(egui::Margin::same(15.0))
                        .show(ui, |ui| {
                            for folder in &self.protected_folders {
                                let exists = PathBuf::from(folder).exists();
                                let (icon, color) = if exists {
                                    ("✅", egui::Color32::from_rgb(100, 255, 150))
                                } else {
                                    ("❌", egui::Color32::from_rgb(255, 100, 100))
                                };
                                
                                ui.horizontal(|ui| {
                                    ui.colored_label(color, icon);
                                    ui.label(egui::RichText::new(folder).size(12.0));
                                });
                                ui.add_space(5.0);
                            }
                        });
                }
            });
        });
    }
    
    fn show_folders(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(20.0);
            ui.vertical(|ui| {
                ui.add_space(10.0);
                ui.label(egui::RichText::new("Protected Workspaces").size(20.0));
                ui.label(egui::RichText::new("Add folders to protect your creative work").size(12.0).color(egui::Color32::GRAY));
                
                ui.add_space(20.0);
                
                if ui.button(egui::RichText::new("➕ Add Workspace").size(14.0)).clicked() {
                    self.show_add_dialog = !self.show_add_dialog;
                }
                
                ui.add_space(15.0);
                
                // Add folder dialog
                if self.show_add_dialog {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(30, 30, 40))
                        .rounding(egui::Rounding::same(8.0))
                        .inner_margin(egui::Margin::same(15.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label("Workspace path:");
                                ui.text_edit_singleline(&mut self.new_folder_input);
                                
                                if ui.button("📂 Browse").clicked() {
                                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                        self.new_folder_input = path.display().to_string();
                                    }
                                }
                                
                                if ui.button("Protect").clicked() && !self.new_folder_input.is_empty() {
                                    if PathBuf::from(&self.new_folder_input).exists() {
                                        self.protected_folders.push(self.new_folder_input.clone());
                                        self.save_config();
                                        self.new_folder_input.clear();
                                        self.show_add_dialog = false;
                                    }
                                }
                                
                                if ui.button("Cancel").clicked() {
                                    self.show_add_dialog = false;
                                    self.new_folder_input.clear();
                                }
                            });
                        });
                    
                    ui.add_space(15.0);
                }
                
                // List protected folders
                let mut to_remove = None;
                
                for (i, folder) in self.protected_folders.iter().enumerate() {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(25, 25, 30))
                        .rounding(egui::Rounding::same(8.0))
                        .inner_margin(egui::Margin::same(15.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let exists = PathBuf::from(folder).exists();
                                let (icon, color) = if exists {
                                    ("✅", egui::Color32::from_rgb(100, 255, 150))
                                } else {
                                    ("❌", egui::Color32::from_rgb(255, 100, 100))
                                };
                                
                                ui.colored_label(color, icon);
                                ui.label(egui::RichText::new(folder).size(14.0));
                                
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button(egui::RichText::new("Remove").color(egui::Color32::from_rgb(255, 100, 100))).clicked() {
                                        to_remove = Some(i);
                                    }
                                });
                            });
                        });
                    
                    ui.add_space(8.0);
                }
                
                if let Some(index) = to_remove {
                    self.protected_folders.remove(index);
                    self.save_config();
                }
            });
        });
    }
    
    fn show_activity(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(20.0);
            ui.vertical(|ui| {
                ui.add_space(10.0);
                ui.label(egui::RichText::new("Protection Activity").size(20.0));
                ui.label(egui::RichText::new("Recent security events and scans").size(12.0).color(egui::Color32::GRAY));
                
                ui.add_space(20.0);
                
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for activity in &self.recent_activity {
                        let is_threat = activity.contains("⚠️") || activity.contains("threat");
                        let color = if is_threat {
                            egui::Color32::from_rgb(255, 150, 150)
                        } else {
                            egui::Color32::LIGHT_GRAY
                        };
                        
                        ui.horizontal(|ui| {
                            ui.add_space(10.0);
                            ui.colored_label(color, activity);
                        });
                        ui.add_space(5.0);
                    }
                });
            });
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    // Initialize crash handler
    crash_handler::initialize_crash_handler();
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 600.0])
            .with_min_inner_size([800.0, 500.0])
            .with_title("MKPE - Protection System"),
        ..Default::default()
    };
    
    eframe::run_native(
        "MKPE Protection System",
        options,
        Box::new(|_cc| Box::new(MkpeApp::default())),
    )
}