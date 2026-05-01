//! MKPE UI - System tray application and control panel

slint::include_modules!();

use anyhow::Result;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;
use tray_icon::{
    menu::{Menu, MenuItem},
    TrayIconBuilder, Icon,
};
use winit::event_loop::{ControlFlow, EventLoopBuilder};

fn load_latest_log() -> String {
    let log_dir = PathBuf::from("C:\\ProgramData\\MKPE\\logs");
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let log_file = log_dir.join(format!("{}.jsonl", today));

    if !log_file.exists() {
        return "No logs for today".to_string();
    }

    match std::fs::read_to_string(&log_file) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let recent: Vec<String> = lines
                .iter()
                .rev()
                .take(10)
                .rev()
                .filter_map(|line| {
                    serde_json::from_str::<Value>(line).ok().map(|v| {
                        format!(
                            "[{}] {} - {}",
                            v["timestamp_utc"].as_str().unwrap_or(""),
                            v["action"].as_str().unwrap_or(""),
                            v["status"].as_str().unwrap_or("")
                        )
                    })
                })
                .collect();
            
            recent.join("\n")
        }
        Err(_) => "Error reading log file".to_string(),
    }
}

fn check_service_status() -> (bool, String, i32, i32, String) {
    // Try to check if service is running
    // For now, just read the log to determine activity
    
    let log_dir = PathBuf::from("C:\\ProgramData\\MKPE\\logs");
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let log_file = log_dir.join(format!("{}.jsonl", today));

    if !log_file.exists() {
        return (false, "Idle".to_string(), 0, 0, "Never".to_string());
    }

    match std::fs::read_to_string(&log_file) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let mut files_checked = 0;
            let mut errors = 0;
            let mut last_scan = "Unknown".to_string();

            for line in lines.iter().rev() {
                if let Ok(entry) = serde_json::from_str::<Value>(line) {
                    if entry["action"] == "scan_completed" {
                        if let Some(details) = entry["details"].as_str() {
                            // Parse "Checked: X, Errors: Y"
                            if let Some(checked_str) = details.split("Checked: ").nth(1) {
                                if let Some(num_str) = checked_str.split(',').next() {
                                    files_checked = num_str.trim().parse().unwrap_or(0);
                                }
                            }
                            if let Some(errors_str) = details.split("Errors: ").nth(1) {
                                errors = errors_str.trim().parse().unwrap_or(0);
                            }
                        }
                        if let Some(timestamp) = entry["timestamp_utc"].as_str() {
                            last_scan = timestamp[11..19].to_string(); // Extract time
                        }
                        break;
                    }
                }
            }

            (true, "Running".to_string(), files_checked, errors, last_scan)
        }
        Err(_) => (false, "Error".to_string(), 0, 0, "Unknown".to_string()),
    }
}

fn load_icon() -> Icon {
    // Try to load the .ico file
    let icon_path = PathBuf::from("C:\\Kalyx\\MKPE\\v1.0.0\\assets\\icons\\mkpe_tray.ico");
    
    if icon_path.exists() {
        if let Ok(icon_data) = std::fs::read(&icon_path) {
            if let Ok(icon) = Icon::from_rgba(vec![0; 32*32*4], 32, 32) {
                return icon;
            }
        }
    }
    
    // Fallback: create a simple colored icon
    let mut rgba = vec![0u8; 32 * 32 * 4];
    for y in 0..32 {
        for x in 0..32 {
            let idx = (y * 32 + x) * 4;
            // Cyan color for MKPE
            rgba[idx] = 0;      // R
            rgba[idx + 1] = 255; // G
            rgba[idx + 2] = 255; // B
            rgba[idx + 3] = 255; // A
        }
    }
    Icon::from_rgba(rgba, 32, 32).unwrap_or_else(|_| {
        Icon::from_rgba(vec![255; 32*32*4], 32, 32).unwrap()
    })
}

fn main() -> Result<()> {
    let event_loop = EventLoopBuilder::new().build().unwrap();
    
    // Create system tray icon
    let tray_menu = Menu::new();
    let show_item = MenuItem::new("Show MKPE", true, None);
    let quit_item = MenuItem::new("Quit", true, None);
    tray_menu.append(&show_item)?;
    tray_menu.append(&quit_item)?;
    
    let icon = load_icon();
    let _tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip("MKPE - Morse-Kirby Provenance Engine")
        .with_icon(icon)
        .build()?;

    let ui = AppWindow::new()?;

    // Initial status update
    let (running, status, files, errors, last) = check_service_status();
    ui.set_service_running(running);
    ui.set_service_status(status.into());
    ui.set_files_checked(files);
    ui.set_errors_found(errors);
    ui.set_last_scan(last.into());
    ui.set_log_text(load_latest_log().into());

    // Set up periodic updates
    let ui_weak = ui.as_weak();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(5));
            
            let ui = match ui_weak.upgrade() {
                Some(ui) => ui,
                None => break,
            };

            let (running, status, files, errors, last) = check_service_status();
            ui.set_service_running(running);
            ui.set_service_status(status.into());
            ui.set_files_checked(files);
            ui.set_errors_found(errors);
            ui.set_last_scan(last.into());
            ui.set_log_text(load_latest_log().into());
        }
    });

    // Handle callbacks
    let ui_handle = ui.as_weak();
    ui.on_run_full_scan(move || {
        // Try multiple possible script locations
        let possible_paths = vec![
            "C:\\Program Files\\MKPE\\service\\Verify-MKPEIntegrity.ps1",
            "C:\\MKPE_Release\\v1.0.0\\service\\Verify-MKPEIntegrity.ps1",
            "C:\\mkpe\\service\\Verify-MKPEIntegrity.ps1",
            ".\\service\\Verify-MKPEIntegrity.ps1",
        ];
        
        let mut scan_started = false;
        for script_path in possible_paths {
            if std::path::Path::new(script_path).exists() {
                if let Ok(_) = std::process::Command::new("powershell")
                    .args(&[
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        script_path,
                        "-Verbose",
                    ])
                    .spawn()
                {
                    scan_started = true;
                    break;
                }
            }
        }
        
        if let Some(ui) = ui_handle.upgrade() {
            if scan_started {
                ui.set_log_text("Scan initiated...\n".into());
            } else {
                ui.set_log_text("Scan script not found. Install MKPE to system location.\n".into());
            }
        }
    });

    let ui_handle2 = ui.as_weak();
    ui.on_pause_service(move || {
        // For now, just update status
        if let Some(ui) = ui_handle2.upgrade() {
            ui.set_service_status("Paused".into());
            ui.set_service_running(false);
        }
    });

    let ui_handle3 = ui.as_weak();
    ui.on_resume_service(move || {
        if let Some(ui) = ui_handle3.upgrade() {
            ui.set_service_status("Running".into());
            ui.set_service_running(true);
        }
    });

    ui.run()?;
    Ok(())
}

