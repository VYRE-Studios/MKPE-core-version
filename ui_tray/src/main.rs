//! MKPE System Tray Application
//! Lightweight tray icon with menu and status window

#![windows_subsystem = "windows"] // No console window

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tray_icon::{
    menu::{Menu, MenuItem, PredefinedMenuItem, MenuEvent},
    TrayIconBuilder, Icon,
};
use winit::event_loop::{ControlFlow, EventLoopBuilder};

struct AppState {
    service_running: bool,
    last_scan_time: String,
    files_checked: i32,
    errors: i32,
}

fn load_icon_from_file() -> Option<Icon> {
    let icon_paths = vec![
        "C:\\Kalyx\\MKPE\\v1.0.0\\assets\\icons\\mkpe_tray.ico",
        "C:\\MKPE\\assets\\icons\\mkpe_tray.ico",
        "C:\\mkpe\\assets\\icons\\mkpe_tray.ico",
        ".\\assets\\icons\\mkpe_tray.ico",
        "mkpe_tray.ico",
    ];
    
    for path in icon_paths {
        if std::path::Path::new(path).exists() {
            if let Ok(image) = image::open(path) {
                let rgba = image.to_rgba8();
                let (width, height) = rgba.dimensions();
                if let Ok(icon) = Icon::from_rgba(rgba.into_raw(), width, height) {
                    return Some(icon);
                }
            }
        }
    }
    
    // Fallback: create a simple icon programmatically
    None
}

fn create_default_icon() -> Icon {
    // Create cyan 32x32 icon
    let size: u32 = 32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    
    for y in 0..size {
        for x in 0..size {
            let idx = ((y * size + x) * 4) as usize;
            // Draw a simple cyan square with border
            if x < 2 || x >= size - 2 || y < 2 || y >= size - 2 {
                // White border
                rgba[idx] = 255;
                rgba[idx + 1] = 255;
                rgba[idx + 2] = 255;
                rgba[idx + 3] = 255;
            } else {
                // Cyan fill
                rgba[idx] = 0;
                rgba[idx + 1] = 255;
                rgba[idx + 2] = 255;
                rgba[idx + 3] = 255;
            }
        }
    }
    
    Icon::from_rgba(rgba, size, size).expect("Failed to create icon")
}

fn check_service_status() -> AppState {
    let log_dir = PathBuf::from("C:\\ProgramData\\MKPE\\logs");
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let log_file = log_dir.join(format!("{}.jsonl", today));

    if !log_file.exists() {
        return AppState {
            service_running: false,
            last_scan_time: "Never".to_string(),
            files_checked: 0,
            errors: 0,
        };
    }

    if let Ok(content) = std::fs::read_to_string(&log_file) {
        let lines: Vec<&str> = content.lines().collect();
        
        for line in lines.iter().rev() {
            if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
                if entry["action"] == "scan_completed" {
                    let details = entry["details"].as_str().unwrap_or("");
                    let mut files = 0;
                    let mut errors = 0;
                    
                    // Parse "Checked: X, Errors: Y"
                    for part in details.split(',') {
                        if part.contains("Checked:") {
                            if let Some(num) = part.split(':').nth(1) {
                                files = num.trim().parse().unwrap_or(0);
                            }
                        }
                        if part.contains("Errors:") {
                            if let Some(num) = part.split(':').nth(1) {
                                errors = num.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                    
                    let timestamp = entry["timestamp_utc"].as_str().unwrap_or("Unknown");
                    let time_only = if timestamp.len() > 11 {
                        &timestamp[11..19]
                    } else {
                        timestamp
                    };
                    
                    return AppState {
                        service_running: true,
                        last_scan_time: time_only.to_string(),
                        files_checked: files,
                        errors,
                    };
                }
            }
        }
    }

    AppState {
        service_running: false,
        last_scan_time: "Unknown".to_string(),
        files_checked: 0,
        errors: 0,
    }
}

fn show_status_message(state: &AppState) {
    let status = if state.service_running {
        format!(
            "MKPE Service: Running\nLast Scan: {}\nFiles: {} | Errors: {}",
            state.last_scan_time, state.files_checked, state.errors
        )
    } else {
        "MKPE Service: Not Running".to_string()
    };
    
    // Simple message box
    #[cfg(windows)]
    unsafe {
        use windows::core::PCSTR;
        use windows::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK, MB_ICONINFORMATION};
        MessageBoxA(
            None,
            PCSTR(format!("{}\0", status).as_ptr()),
            PCSTR(b"MKPE Status\0".as_ptr()),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let event_loop = EventLoopBuilder::new().build()?;
    
    // Load icon
    let icon = load_icon_from_file().unwrap_or_else(|| create_default_icon());
    
    // Create menu
    let tray_menu = Menu::new();
    let show_status = MenuItem::new("Show Status", true, None);
    let separator = PredefinedMenuItem::separator();
    let quit = MenuItem::new("Quit MKPE", true, None);
    
    tray_menu.append(&show_status)?;
    tray_menu.append(&separator)?;
    tray_menu.append(&quit)?;
    
    // Build tray icon
    let tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip("MKPE - Provenance Engine")
        .with_icon(icon)
        .build()?;
    
    let state = Arc::new(Mutex::new(check_service_status()));
    
    // Update status periodically
    let state_update = state.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(5));
            let new_state = check_service_status();
            if let Ok(mut s) = state_update.lock() {
                *s = new_state;
            }
        }
    });
    
    // Handle menu clicks
    let show_status_id = show_status.id().clone();
    let quit_id = quit.id().clone();
    let state_clone = state.clone();
    
    let menu_channel = MenuEvent::receiver();
    
    // Run event loop
    event_loop.run(move |_event, elwt| {
        elwt.set_control_flow(ControlFlow::WaitUntil(
            std::time::Instant::now() + Duration::from_millis(100)
        ));
        
        // Check for menu events
        if let Ok(event) = menu_channel.try_recv() {
            if event.id == show_status_id {
                let current_state = state_clone.lock().unwrap();
                show_status_message(&current_state);
            } else if event.id == quit_id {
                elwt.exit();
            }
        }
    })?;
    
    Ok(())
}

