//! Audit logging system for MKPE
//!
//! Provides an append-only, structured log of all verification events.

use crate::{MkpeError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
	use std::fs::OpenOptions;
	use std::io::{BufRead, Write};
	use std::path::{Path, PathBuf};

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
		/// Optional hash linking to the previous audit entry for chain integrity
		#[serde(skip_serializing_if = "Option::is_none")]
		pub previous_hash: Option<String>,
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
			previous_hash: None,
		}
	}

	/// Set the previous hash for chain linking
	pub fn with_previous_hash(mut self, hash: String) -> Self {
		self.previous_hash = Some(hash);
		self
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
            "INFO",
        ))
    }

    /// Convenience: Log a verification failure/tampering
    pub fn log_failure(&self, target: &str, reason: &str) -> Result<()> {
        self.log(&AuditEvent::new(
            AuditEventType::VerificationFailure,
            Some(target.to_string()),
            format!("Verification FAILED: {}", reason),
            "CRITICAL",
        ))
    }

	/// Read all audit entries from the log file
	pub fn read_entries(&self) -> Result<Vec<AuditEvent>> {
		let mut entries = Vec::new();
		let file = std::fs::File::open(&self.log_path).map_err(MkpeError::IoError)?;
		let reader = std::io::BufReader::new(file);
		for line in reader.lines() {
			let line = line.map_err(MkpeError::IoError)?;
			if line.trim().is_empty() {
				continue;
			}
			let event: AuditEvent = serde_json::from_str(&line).map_err(MkpeError::JsonError)?;
			entries.push(event);
		}
		Ok(entries)
	}

	/// Compute SHA-256 hash of a single audit event JSON
	fn entry_hash(event: &AuditEvent) -> String {
		use sha2::{Digest, Sha256};
		let json = serde_json::to_string(event).unwrap_or_default();
		let mut hasher = Sha256::new();
		hasher.update(json.as_bytes());
		hex::encode(hasher.finalize())
	}

	/// Compute the Merkle root of all entries in the log
	pub fn compute_merkle_root(&self) -> Result<Option<String>> {
		let entries = self.read_entries()?;
		if entries.is_empty() {
			return Ok(None);
		}
		let hashes: Vec<String> = entries.iter().map(|e| Self::entry_hash(e)).collect();
		Ok(Some(crate::proof::build_merkle_root(&hashes)))
	}

	/// Verify chain integrity: every entry's previous_hash must match the hash of the prior entry
	pub fn verify_chain(&self) -> Result<bool> {
		let entries = self.read_entries()?;
		if entries.len() < 2 {
			return Ok(true);
		}
		for i in 1..entries.len() {
			let prev_hash = Self::entry_hash(&entries[i - 1]);
			if entries[i].previous_hash.as_deref() != Some(prev_hash.as_str()) {
				return Ok(false);
			}
		}
		Ok(true)
	}

	/// Log an event with automatic chain linking to the previous entry
	pub fn log_chained(&self, event: AuditEvent) -> Result<()> {
		let mut event = event;
		if let Ok(entries) = self.read_entries() {
			if let Some(last) = entries.last() {
				event.previous_hash = Some(Self::entry_hash(last));
			}
		}
		self.log(&event)
	}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use tempfile::NamedTempFile;

    #[test]
    fn test_audit_log_creation() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        let log = AuditLog::new(temp_file.path())?;

        let event = AuditEvent::new(
            AuditEventType::SystemStart,
            None,
            "System started".to_string(),
            "INFO",
        );

        log.log(&event)?;

        let file = std::fs::File::open(temp_file.path())?;
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

        let file = std::fs::File::open(temp_file.path())?;
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

        let file = std::fs::File::open(temp_file.path())?;
        let reader = std::io::BufReader::new(file);
        let line = reader.lines().next().unwrap()?;

        let loaded: AuditEvent = serde_json::from_str(&line)?;
        assert_eq!(loaded.event_type, AuditEventType::VerificationFailure);
        assert_eq!(loaded.severity, "CRITICAL");

        Ok(())
    }
}
