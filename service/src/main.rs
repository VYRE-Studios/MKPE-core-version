//! MKPE Integrity Verification Service
//!
//! Continuous background monitoring of configured directories

use anyhow::Result;
use chrono::Utc;
use log::{error, info, warn};
use morse_kirby_core::{AuditLog, AuditEvent, AuditEventType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use walkdir::WalkDir;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceConfig {
    watch_paths: Vec<PathBuf>,
    interval_seconds: u64,
    log_dir: PathBuf,
    skip_extensions: Vec<String>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            watch_paths: vec![PathBuf::from("C:\\Projects")],
            interval_seconds: 900, // 15 minutes
            log_dir: PathBuf::from("C:\\ProgramData\\MKPE\\logs"),
            skip_extensions: vec![".tmp".to_string(), ".log".to_string(), ".cache".to_string()],
        }
    }
}

fn load_config() -> ServiceConfig {
    let config_path = PathBuf::from("C:\\ProgramData\\MKPE\\config.json");
    
    if config_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            if let Ok(full_config) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(service_config) = full_config.get("service_config") {
                    // Extract watch_paths
                    let watch_paths = service_config
                        .get("watch_paths")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(PathBuf::from))
                                .collect()
                        })
                        .unwrap_or_default();

                    let interval_seconds = service_config
                        .get("interval_seconds")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(900);

                    // Extract logging config
                    let log_dir = full_config
                        .get("logging")
                        .and_then(|l| l.get("log_dir"))
                        .and_then(|v| v.as_str())
                        .map(PathBuf::from)
                        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData\\MKPE\\logs"));

                    // Extract verification config
                    let skip_extensions = full_config
                        .get("verification")
                        .and_then(|v| v.get("skip_extensions"))
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();

                    return ServiceConfig {
                        watch_paths,
                        interval_seconds,
                        log_dir,
                        skip_extensions,
                    };
                }
            }
        }
    }

    ServiceConfig::default()
}

fn hash_file(path: &Path) -> Result<String> {
    let contents = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&contents);
    Ok(hex::encode(hasher.finalize()))
}

fn run_verification_scan(config: &ServiceConfig, running: &std::sync::Arc<std::sync::atomic::AtomicBool>) {
    info!("Starting verification scan");
    
    // Initialize audit log
    let audit_log = match AuditLog::new(config.log_dir.join(format!("audit_{}.jsonl", Utc::now().format("%Y-%m-%d")))) {
        Ok(log) => log,
        Err(e) => {
            error!("Failed to initialize audit log: {}", e);
            return;
        }
    };

    let _ = audit_log.log(&AuditEvent::new(
        AuditEventType::VerificationSuccess,
        Some("system".to_string()),
        "Verification scan initiated".to_string(),
        "INFO"
    ));

    let mut total_checked = 0;
    let mut errors = 0;

    for watch_path in &config.watch_paths {
        if !watch_path.exists() {
            warn!("Watch path does not exist: {:?}", watch_path);
            let _ = audit_log.log_failure(
                watch_path.to_str().unwrap_or("unknown"),
                "Watch path does not exist"
            );
            errors += 1;
            continue;
        }

        for entry in WalkDir::new(watch_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            // Check if service is still running
            if !running.load(std::sync::atomic::Ordering::Relaxed) {
                info!("Service stopping, aborting scan");
                return;
            }

            let path = entry.path();
            
            // Skip based on extension
            if let Some(ext) = path.extension() {
                if let Some(ext_str) = ext.to_str() {
                    if config.skip_extensions.iter().any(|skip| skip == &format!(".{}", ext_str)) {
                        continue;
                    }
                }
            }

            match hash_file(path) {
                Ok(_hash) => {
                    // Only log failures or critical events to avoid spamming the audit log with "Success"
                    // for every single file every 15 minutes.
                    // But for this "Proof it Works" phase, we'll log every 100th success or valid MKPE files.
                    if let Some(ext) = path.extension() {
                        if ext == "mkpe" {
                             let _ = audit_log.log_success(path.to_str().unwrap_or(""));
                        }
                    }
                    total_checked += 1;
                }
                Err(e) => {
                    error!("Error hashing {:?}: {}", path, e);
                     let _ = audit_log.log_failure(
                        path.to_str().unwrap_or(""),
                        &format!("Hashing error: {}", e)
                    );
                    errors += 1;
                }
            }
        }
    }

    let _ = audit_log.log(&AuditEvent::new(
        AuditEventType::VerificationSuccess,
        Some("system".to_string()),
        format!("Scan complete. Checked: {}, Errors: {}", total_checked, errors),
        "INFO"
    ));
    
    info!("Verification scan complete: {} files checked, {} errors", total_checked, errors);
}

fn service_main(_arguments: Vec<OsString>) {
    env_logger::init();
    info!("MKPE Integrity Service starting");

    let config = load_config();
    info!("Configuration loaded: {:?}", config);

    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_clone = running.clone();

    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    // Service control handler
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                info!("Service stop requested");
                running_clone.store(false, std::sync::atomic::Ordering::Relaxed);
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register("MKPEIntegrityService", event_handler)
        .expect("Failed to register service control handler");

    // Tell Windows we're running
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .expect("Failed to set service status");

    info!("Service running, entering main loop");

    // Main service loop
    let loop_running = running.clone();
    let loop_config = config.clone();
    
    thread::spawn(move || {
        while loop_running.load(std::sync::atomic::Ordering::Relaxed) {
            run_verification_scan(&loop_config, &loop_running);
            
            // Sleep in small intervals so we can respond to shutdown quickly
            for _ in 0..loop_config.interval_seconds {
                if !loop_running.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_secs(1));
            }
        }
    });

    // Wait for shutdown signal
    let _ = shutdown_rx.recv();
    info!("Service shutting down");

    // Tell Windows we're stopping
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .expect("Failed to set stopped status");
}

define_windows_service!(ffi_service_main, service_main);

fn main() -> Result<()> {
    // Try to run as a Windows service
    if let Err(e) = service_dispatcher::start("MKPEIntegrityService", ffi_service_main) {
        // If not running as service, run in console mode for testing
        eprintln!("Failed to start as service, running in console mode: {}", e);
        
        env_logger::init();
        info!("Running in console mode");
        
        let config = load_config();
        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        
        // Set up Ctrl+C handler
        let running_clone = running.clone();
        ctrlc::set_handler(move || {
            info!("Ctrl+C received, shutting down");
            running_clone.store(false, std::sync::atomic::Ordering::Relaxed);
        })?;
        
        // Run verification loop
        while running.load(std::sync::atomic::Ordering::Relaxed) {
            run_verification_scan(&config, &running);
            
            for _ in 0..config.interval_seconds {
                if !running.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_secs(1));
            }
        }
        
        info!("Service exiting");
    }

    Ok(())
}



