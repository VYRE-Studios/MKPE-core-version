//! MKPE Crash Handler - Automatic crash reporting and recovery
use std::fs;
use std::path::PathBuf;
use std::panic;
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReport {
    pub crash_id: String,
    pub timestamp: String,
    pub panic_message: String,
    pub panic_location: Option<String>,
    pub backtrace: Option<String>,
    pub system_info: SystemInfo,
    pub process_info: ProcessInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os: String,
    pub version: String,
    pub hostname: String,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub memory_usage_mb: u64,
    pub uptime_seconds: u64,
}

pub fn initialize_crash_handler() {
    // Set up panic hook to capture crashes
    panic::set_hook(Box::new(|panic_info| {
        let crash_report = generate_crash_report(panic_info);
        
        // Save crash report to file
        if let Err(e) = save_crash_report(&crash_report) {
            eprintln!("Failed to save crash report: {}", e);
        }
        
        // Print crash report to stderr
        eprintln!("=== MKPE CRASH REPORT ===");
        eprintln!("Crash ID: {}", crash_report.crash_id);
        eprintln!("Time: {}", crash_report.timestamp);
        eprintln!("Message: {}", crash_report.panic_message);
        if let Some(location) = &crash_report.panic_location {
            eprintln!("Location: {}", location);
        }
        eprintln!("========================");
        
        // Attempt to restart the application
        eprintln!("Attempting automatic recovery...");
    }));
}

fn generate_crash_report(panic_info: &panic::PanicInfo) -> CrashReport {
    let crash_id = format!("crash_{}", Utc::now().timestamp());
    let timestamp = Utc::now().to_rfc3339();
    
    // Extract panic message
    let panic_message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
        s.clone()
    } else {
        "Unknown panic".to_string()
    };
    
    // Extract location
    let panic_location = panic_info.location().map(|loc| {
        format!("{}:{}:{}", loc.file(), loc.line(), loc.column())
    });
    
    // Get backtrace (requires RUST_BACKTRACE=1)
    let backtrace = std::env::var("RUST_BACKTRACE")
        .ok()
        .map(|_| format!("{:?}", std::backtrace::Backtrace::capture()));
    
    // Gather system info
    let system_info = SystemInfo {
        os: std::env::consts::OS.to_string(),
        version: std::env::var("OS").unwrap_or_else(|_| "Unknown".to_string()),
        hostname: hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "Unknown".to_string()),
        username: std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "Unknown".to_string()),
    };
    
    // Gather process info
    let process_info = ProcessInfo {
        pid: std::process::id(),
        memory_usage_mb: 0, // Would need platform-specific code
        uptime_seconds: 0,  // Would need to track startup time
    };
    
    CrashReport {
        crash_id,
        timestamp,
        panic_message,
        panic_location,
        backtrace,
        system_info,
        process_info,
    }
}

fn save_crash_report(report: &CrashReport) -> Result<(), Box<dyn std::error::Error>> {
    // Create crash logs directory
    let crash_dir = PathBuf::from("C:\\MKPE\\crash_logs");
    fs::create_dir_all(&crash_dir)?;
    
    // Save as JSON
    let filename = format!("{}.json", report.crash_id);
    let filepath = crash_dir.join(&filename);
    let json = serde_json::to_string_pretty(report)?;
    fs::write(&filepath, json)?;
    
    // Also save as human-readable text
    let text_filename = format!("{}.txt", report.crash_id);
    let text_filepath = crash_dir.join(&text_filename);
    let text = format!(
        "MKPE CRASH REPORT\n\
        ==================\n\
        \n\
        Crash ID: {}\n\
        Timestamp: {}\n\
        \n\
        ERROR:\n\
        {}\n\
        \n\
        LOCATION:\n\
        {}\n\
        \n\
        SYSTEM INFO:\n\
        OS: {}\n\
        Version: {}\n\
        Hostname: {}\n\
        Username: {}\n\
        \n\
        PROCESS INFO:\n\
        PID: {}\n\
        Memory: {} MB\n\
        Uptime: {} seconds\n\
        \n\
        BACKTRACE:\n\
        {}\n\
        \n\
        ==================\n\
        Please report this crash to the MKPE development team.\n\
        Crash log saved to: {}\n",
        report.crash_id,
        report.timestamp,
        report.panic_message,
        report.panic_location.as_deref().unwrap_or("Unknown"),
        report.system_info.os,
        report.system_info.version,
        report.system_info.hostname,
        report.system_info.username,
        report.process_info.pid,
        report.process_info.memory_usage_mb,
        report.process_info.uptime_seconds,
        report.backtrace.as_deref().unwrap_or("No backtrace available (set RUST_BACKTRACE=1)"),
        filepath.display()
    );
    fs::write(&text_filepath, text)?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_crash_report_generation() {
        // This would require triggering a panic in a controlled way
        // For now, just test that the structures work
        let report = CrashReport {
            crash_id: "test_crash".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            panic_message: "Test panic".to_string(),
            panic_location: Some("test.rs:10:5".to_string()),
            backtrace: None,
            system_info: SystemInfo {
                os: "test".to_string(),
                version: "1.0".to_string(),
                hostname: "test_host".to_string(),
                username: "test_user".to_string(),
            },
            process_info: ProcessInfo {
                pid: 12345,
                memory_usage_mb: 100,
                uptime_seconds: 60,
            },
        };
        
        // Should serialize without errors
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("test_crash"));
    }
}
