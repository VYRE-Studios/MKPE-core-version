//! MKPE Integrity Verification Service
//!
//! Continuous background monitoring of configured directories

use anyhow::Result;
use chrono::Utc;
use log::{error, info, warn};
use morse_kirby_core::{
    create_mkpe_bundle, default_sidecar_path, AuditEvent, AuditEventType, AuditLog, KeyPair,
    MkpeArchive,
};
use serde::{Deserialize, Serialize};
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
    key_path: Option<PathBuf>,
    auto_create_missing_proofs: bool,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            watch_paths: Vec::new(),
            interval_seconds: 900, // 15 minutes
            log_dir: PathBuf::from("C:\\ProgramData\\MKPE\\logs"),
            skip_extensions: vec![".tmp".to_string(), ".log".to_string(), ".cache".to_string()],
            key_path: Some(PathBuf::from(
                "C:\\ProgramData\\MKPE\\keys\\mkpe_private.key",
            )),
            auto_create_missing_proofs: false,
        }
    }
}

fn load_config() -> Result<ServiceConfig> {
    let config_path = PathBuf::from("C:\\ProgramData\\MKPE\\config.json");
    let defaults = ServiceConfig::default();

    if !config_path.exists() {
        return Ok(defaults);
    }

    let content = std::fs::read_to_string(&config_path)?;
    load_config_from_str(&content)
}

fn load_config_from_str(content: &str) -> Result<ServiceConfig> {
    let defaults = ServiceConfig::default();
    let full_config = serde_json::from_str::<serde_json::Value>(content)?;
    let service_config = full_config
        .get("service_config")
        .ok_or_else(|| anyhow::anyhow!("Missing service_config section"))?;

    let watch_paths = service_config
        .get("watch_paths")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(PathBuf::from))
                .collect()
        })
        .unwrap_or_else(|| defaults.watch_paths.clone());

    let interval_seconds = service_config
        .get("interval_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(defaults.interval_seconds);

    let log_dir = full_config
        .get("logging")
        .and_then(|l| l.get("log_dir"))
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or(defaults.log_dir);

    let skip_extensions = full_config
        .get("verification")
        .and_then(|v| v.get("skip_extensions"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or(defaults.skip_extensions);

    let key_path = full_config
        .get("signing")
        .and_then(|v| v.get("key_path"))
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .or(defaults.key_path);

    let auto_create_missing_proofs = service_config
        .get("auto_create_missing_proofs")
        .and_then(|v| v.as_bool())
        .unwrap_or(defaults.auto_create_missing_proofs);

    Ok(ServiceConfig {
        watch_paths,
        interval_seconds,
        log_dir,
        skip_extensions,
        key_path,
        auto_create_missing_proofs,
    })
}

fn load_service_keypair(config: &ServiceConfig) -> Option<KeyPair> {
    let key_path = config.key_path.as_ref()?;
    let private_key = std::fs::read_to_string(key_path).ok()?;
    let public_key_path = key_path.with_file_name("mkpe_public.key");
    let public_key = std::fs::read_to_string(public_key_path).ok()?;

    Some(KeyPair::new(
        private_key.trim().to_string(),
        public_key.trim().to_string(),
        "service".to_string(),
    ))
}

fn should_skip_file(path: &Path, config: &ServiceConfig) -> bool {
    if path.file_name().and_then(|name| name.to_str()) == Some(".mkpe") {
        return true;
    }

    if path.extension().and_then(|ext| ext.to_str()) == Some("mkpe") {
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            return true;
        };
        if let Some(original_name) = file_name.strip_suffix(".mkpe") {
            if path.with_file_name(original_name).exists() {
                return true;
            }
        }
    }

    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            config
                .skip_extensions
                .iter()
                .any(|skip| skip == &format!(".{}", ext))
        })
        .unwrap_or(false)
}

fn sidecar_path_for(path: &Path) -> PathBuf {
    default_sidecar_path(path)
}

fn audit_event(audit_log: &AuditLog, event: &AuditEvent) -> bool {
    match audit_log.log(event) {
        Ok(()) => true,
        Err(error) => {
            error!("Failed to write audit event: {}", error);
            false
        }
    }
}

fn audit_failure(audit_log: &AuditLog, target: &str, reason: &str) -> bool {
    match audit_log.log_failure(target, reason) {
        Ok(()) => true,
        Err(error) => {
            error!("Failed to write audit failure: {}", error);
            false
        }
    }
}

fn verify_or_create_sidecar(
    path: &Path,
    config: &ServiceConfig,
    audit_log: &AuditLog,
    keypair: Option<&KeyPair>,
) -> bool {
    let sidecar_path = sidecar_path_for(path);

    if sidecar_path.exists() {
        match MkpeArchive::load(&sidecar_path).and_then(|archive| archive.verify_artifact(path)) {
            Ok(report) => audit_event(
                audit_log,
                &AuditEvent::new(
                    AuditEventType::VerificationSuccess,
                    Some(path.to_string_lossy().to_string()),
                    format!(
                        "DNA proof verified. Sidecar: {}, proofs: {}, root: {}",
                        sidecar_path.display(),
                        report.verified_proofs,
                        report.root_hash
                    ),
                    "INFO",
                ),
            ),
            Err(error) => {
                audit_failure(
                    audit_log,
                    path.to_str().unwrap_or(""),
                    &format!("DNA proof mismatch: {}", error),
                );
                false
            }
        }
    } else if config.auto_create_missing_proofs {
        match keypair {
            Some(keypair) => match create_mkpe_bundle(path, keypair, sidecar_path.as_path()) {
                Ok(archive) => audit_event(
                    audit_log,
                    &AuditEvent::new(
                        AuditEventType::BundleCreated,
                        Some(path.to_string_lossy().to_string()),
                        format!(
                            "DNA sidecar created at {} with root {}",
                            sidecar_path.display(),
                            archive.manifest.bundle_root_hash
                        ),
                        "INFO",
                    ),
                ),
                Err(error) => {
                    audit_failure(
                        audit_log,
                        path.to_str().unwrap_or(""),
                        &format!("Failed to create DNA sidecar: {}", error),
                    );
                    false
                }
            },
            None => {
                audit_failure(
                    audit_log,
                    path.to_str().unwrap_or(""),
                    "Missing MKPE DNA sidecar and no service signing key configured",
                );
                false
            }
        }
    } else {
        audit_failure(
            audit_log,
            path.to_str().unwrap_or(""),
            "Missing MKPE DNA sidecar",
        );
        false
    }
}

fn run_verification_scan(
    config: &ServiceConfig,
    running: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    info!("Starting verification scan");

    // Initialize audit log
    let audit_log = match AuditLog::new(
        config
            .log_dir
            .join(format!("audit_{}.jsonl", Utc::now().format("%Y-%m-%d"))),
    ) {
        Ok(log) => log,
        Err(e) => {
            error!("Failed to initialize audit log: {}", e);
            return;
        }
    };

    if !audit_event(
        &audit_log,
        &AuditEvent::new(
            AuditEventType::VerificationSuccess,
            Some("system".to_string()),
            "Verification scan initiated".to_string(),
            "INFO",
        ),
    ) {
        return;
    }

    let mut total_checked = 0;
    let mut errors = 0;
    let service_keypair = load_service_keypair(config);

    for watch_path in &config.watch_paths {
        if !watch_path.exists() {
            warn!("Watch path does not exist: {:?}", watch_path);
            audit_failure(
                &audit_log,
                watch_path.to_str().unwrap_or("unknown"),
                "Watch path does not exist",
            );
            errors += 1;
            continue;
        }

        for entry in WalkDir::new(watch_path).into_iter() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    errors += 1;
                    let path = error
                        .path()
                        .map(|path| path.to_string_lossy().to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    audit_failure(
                        &audit_log,
                        &path,
                        &format!("Traversal error during DNA scan: {}", error),
                    );
                    continue;
                }
            };

            if !entry.file_type().is_file() {
                continue;
            }

            // Check if service is still running
            if !running.load(std::sync::atomic::Ordering::Relaxed) {
                info!("Service stopping, aborting scan");
                return;
            }

            let path = entry.path();

            if should_skip_file(path, config) {
                continue;
            }

            total_checked += 1;
            if !verify_or_create_sidecar(path, config, &audit_log, service_keypair.as_ref()) {
                errors += 1;
            }
        }
    }

    audit_event(
        &audit_log,
        &AuditEvent::new(
            AuditEventType::VerificationSuccess,
            Some("system".to_string()),
            format!(
                "Scan complete. Checked: {}, Errors: {}",
                total_checked, errors
            ),
            "INFO",
        ),
    );

    info!(
        "Verification scan complete: {} files checked, {} errors",
        total_checked, errors
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use morse_kirby_core::{generate_keypair, MkpeArchive};
    use tempfile::TempDir;

    #[test]
    fn test_sidecar_path_preserves_full_file_name() {
        let temp_dir = TempDir::new().unwrap();
        let txt = temp_dir.path().join("report.txt");
        let pdf = temp_dir.path().join("report.pdf");

        assert_eq!(
            sidecar_path_for(&txt),
            temp_dir.path().join("report.txt.mkpe")
        );
        assert_eq!(
            sidecar_path_for(&pdf),
            temp_dir.path().join("report.pdf.mkpe")
        );
        assert_ne!(sidecar_path_for(&txt), sidecar_path_for(&pdf));
    }

    #[test]
    fn test_should_skip_only_recognized_sidecars_not_mkpe_payloads() {
        let temp_dir = TempDir::new().unwrap();
        let config = ServiceConfig::default();

        let payload = temp_dir.path().join("payload.mkpe");
        std::fs::write(&payload, b"payload bytes").unwrap();
        assert!(!should_skip_file(&payload, &config));

        let artifact = temp_dir.path().join("report.txt");
        let sidecar = temp_dir.path().join("report.txt.mkpe");
        std::fs::write(&artifact, b"report bytes").unwrap();
        std::fs::write(&sidecar, b"sidecar bytes").unwrap();
        assert!(should_skip_file(&sidecar, &config));
    }

    #[test]
    fn test_load_config_requires_service_config_section() {
        let config = r#"{"logging":{"log_dir":"C:\\Temp\\MKPE"}}"#;
        assert!(load_config_from_str(config).is_err());
    }

    #[test]
    fn test_verify_or_create_sidecar_handles_same_stem_files() {
        let temp_dir = TempDir::new().unwrap();
        let keypair = generate_keypair();
        let private_key_path = temp_dir.path().join("mkpe_private.key");
        let public_key_path = temp_dir.path().join("mkpe_public.key");
        std::fs::write(&private_key_path, &keypair.private_key).unwrap();
        std::fs::write(&public_key_path, &keypair.public_key).unwrap();

        let txt = temp_dir.path().join("report.txt");
        let pdf = temp_dir.path().join("report.pdf");
        std::fs::write(&txt, b"text report").unwrap();
        std::fs::write(&pdf, b"pdf report").unwrap();

        let log_dir = temp_dir.path().join("logs");
        let config = ServiceConfig {
            watch_paths: vec![temp_dir.path().to_path_buf()],
            interval_seconds: 1,
            log_dir: log_dir.clone(),
            skip_extensions: Vec::new(),
            key_path: Some(private_key_path),
            auto_create_missing_proofs: true,
        };
        let audit_log = AuditLog::new(log_dir.join("audit.jsonl")).unwrap();

        assert!(verify_or_create_sidecar(
            &txt,
            &config,
            &audit_log,
            Some(&keypair)
        ));
        assert!(verify_or_create_sidecar(
            &pdf,
            &config,
            &audit_log,
            Some(&keypair)
        ));

        let txt_sidecar = temp_dir.path().join("report.txt.mkpe");
        let pdf_sidecar = temp_dir.path().join("report.pdf.mkpe");
        assert!(txt_sidecar.exists());
        assert!(pdf_sidecar.exists());
        assert_ne!(txt_sidecar, pdf_sidecar);

        MkpeArchive::load(&txt_sidecar)
            .unwrap()
            .verify_artifact(&txt)
            .unwrap();
        MkpeArchive::load(&pdf_sidecar)
            .unwrap()
            .verify_artifact(&pdf)
            .unwrap();
    }
}

fn service_main(_arguments: Vec<OsString>) {
    env_logger::init();
    info!("MKPE Integrity Service starting");

    let config = match load_config() {
        Ok(config) => config,
        Err(error) => {
            error!("Failed to load service configuration: {}", error);
            return;
        }
    };
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

        let config = load_config()?;
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
