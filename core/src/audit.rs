//! Audit logging system for MKPE
//!
//! Provides an append-only, structured log of all verification events.

use crate::{Result, MkpeError};
use serde::{Deserialize, Serialize};
use std::fs::{OpenOptions, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};

/// Types of audit events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditEventType {
    /// System startup
    SystemStart,
    /// System shutdown
    SystemStop,
    /// Verification succeeded
    VerificationSuccess,
    /// Verification failed (tampering detected)
    VerificationFailure,
    /// New bundle created
    BundleCreated,
    /// Configuration change
    ConfigChange,
    /// Error during operation
    SystemError,
}

/// A single audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique ID for this event
    pub id: String,
    /// Timestamp (UTC)
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: AuditEventType,
    /// Involved file or resource (optional)
    pub target: Option<String>,
    /// Detailed message
    pub message: String,
    /// System user
    pub user: String,
    /// Severity (INFO, WARN, ERROR, CRITICAL)
    pub severity: String,
}

impl AuditEvent {
    pub fn new(
        event_type: AuditEventType,
        target: Option<String>,
        message: String,
        severity: &str,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            target,
            message,
            user: whoami::username(),
            severity: severity.to_string(),
        }
    }
}

/// Audit log manager
pub struct AuditLog {
    log_path: PathBuf,
}

impl AuditLog {
    /// Open or create an audit log at the specified path
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        Ok(Self { log_path: path })
    }

    /// Record an event to the log
    pub fn log(&self, event: &AuditEvent) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        let json = serde_json::to_string(event)
            .map_err(|e| MkpeError::AuditError(format!("Serialization error: {}", e)))?;
            
        writeln!(file, "{}", json)?;
        Ok(())
    }

    /// Convenience: Log a verification success
    pub fn log_success(&self, target: &str) -> Result<()> {
        self.log(&AuditEvent::new(
            AuditEventType::VerificationSuccess,
            Some(target.to_string()),
            "Verification succeeded".to_string(),
            "INFO"
        ))
    }

    /// Convenience: Log a verification failure/tampering
    pub fn log_failure(&self, target: &str, reason: &str) -> Result<()> {
        self.log(&AuditEvent::new(
            AuditEventType::VerificationFailure,
            Some(target.to_string()),
            format!("Verification FAILED: {}", reason),
            "CRITICAL"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::BufRead;

    #[test]
    fn test_audit_log_creation() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        let log = AuditLog::new(temp_file.path())?;
        
        let event = AuditEvent::new(
            AuditEventType::SystemStart,
            None,
            "System started".to_string(),
            "INFO"
        );
        
        log.log(&event)?;
        
        let file = File::open(temp_file.path())?;
        let reader = std::io::BufReader::new(file);
        let line = reader.lines().next().unwrap()?;
        
        let loaded: AuditEvent = serde_json::from_str(&line)?;
        assert_eq!(loaded.message, "System started");
        assert_eq!(loaded.event_type, AuditEventType::SystemStart);
        
        Ok(())
    }

    #[test]
    fn test_audit_success() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        let log = AuditLog::new(temp_file.path())?;
        
        log.log_success("test.mkpe")?;
        
        let file = File::open(temp_file.path())?;
        let reader = std::io::BufReader::new(file);
        let line = reader.lines().next().unwrap()?;
        
        let loaded: AuditEvent = serde_json::from_str(&line)?;
        assert_eq!(loaded.event_type, AuditEventType::VerificationSuccess);
        
        Ok(())
    }

     #[test]
    fn test_audit_failure() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        let log = AuditLog::new(temp_file.path())?;
        
        log.log_failure("bad.mkpe", "Signature mismatch")?;
        
        let file = File::open(temp_file.path())?;
        let reader = std::io::BufReader::new(file);
        let line = reader.lines().next().unwrap()?;
        
        let loaded: AuditEvent = serde_json::from_str(&line)?;
        assert_eq!(loaded.event_type, AuditEventType::VerificationFailure);
        assert_eq!(loaded.severity, "CRITICAL");
        
        Ok(())
    }
}
