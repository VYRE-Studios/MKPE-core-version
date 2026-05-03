//! Build attestation support for MKPE Layer 3.

use crate::{crypto::verify_signature, KeyPair, MkpeArchive, MkpeError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const ATTESTATION_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttestationSubjectKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildFingerprint {
    pub user: String,
    pub platform: String,
    pub hostname: String,
    pub process_id: u32,
    pub architecture: String,
    pub mkpe_version: String,
    pub working_directory: String,
}

impl BuildFingerprint {
    pub fn capture() -> Self {
        Self {
            user: whoami::username(),
            platform: whoami::platform().to_string(),
            hostname: whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
            process_id: std::process::id(),
            architecture: std::env::consts::ARCH.to_string(),
            mkpe_version: crate::MKPE_VERSION.to_string(),
            working_directory: std::env::current_dir()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AttestationOptions {
    pub attested_by: String,
    pub command: Option<String>,
    pub bundle_path: Option<PathBuf>,
}

impl Default for AttestationOptions {
    fn default() -> Self {
        Self {
            attested_by: whoami::username(),
            command: None,
            bundle_path: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AttestationVerificationOptions {
    pub subject_path: Option<PathBuf>,
    pub trusted_public_key: Option<String>,
    pub bundle_path: Option<PathBuf>,
}

	#[derive(Debug, Clone, Serialize, Deserialize)]
	#[serde(deny_unknown_fields)]
	pub struct BuildAttestation {
		pub schema_version: String,
		pub attestation_id: String,
		pub subject_path: String,
		pub subject_kind: AttestationSubjectKind,
		pub subject_sha256: String,
		pub bundle_manifest_id: Option<String>,
		pub bundle_root_hash: Option<String>,
		pub build_fingerprint: BuildFingerprint,
		pub build_info: Option<BuildInfo>,
		pub command: Option<String>,
		pub timestamp_utc: chrono::DateTime<chrono::Utc>,
		pub attested_by: String,
		pub signer_public_key: String,
		pub signature: String,
		pub nonce: Option<u64>,
	}

	/// Build provenance metadata for SLSA-like attestations
	#[derive(Debug, Clone, Serialize, Deserialize)]
	pub struct BuildInfo {
		pub builder_id: String,
		pub build_type: String,
		pub build_definition: String,
		pub source_repository: Option<String>,
		pub source_commit: Option<String>,
		pub dependencies: Vec<Dependency>,
		pub environment: std::collections::HashMap<String, String>,
	}

	/// A single dependency with integrity hash
	#[derive(Debug, Clone, Serialize, Deserialize)]
	pub struct Dependency {
		pub name: String,
		pub version: String,
		pub source: String,
		pub integrity: String,
	}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationVerificationReport {
    pub attestation_id: String,
    pub subject_sha256: String,
    pub trusted_signer: bool,
    pub signer_public_key: String,
    pub bundle_manifest_id: Option<String>,
    pub bundle_root_hash: Option<String>,
}

	#[derive(Debug, Clone, Serialize)]
	struct AttestationSigningPayload<'a> {
		schema_version: &'a str,
		attestation_id: &'a str,
		subject_path: &'a str,
		subject_kind: &'a AttestationSubjectKind,
		subject_sha256: &'a str,
		bundle_manifest_id: &'a Option<String>,
		bundle_root_hash: &'a Option<String>,
		build_fingerprint: &'a BuildFingerprint,
		command: &'a Option<String>,
		timestamp_utc: &'a chrono::DateTime<chrono::Utc>,
		attested_by: &'a str,
		signer_public_key: &'a str,
		#[serde(skip_serializing_if = "Option::is_none")]
		nonce: &'a Option<u64>,
		#[serde(skip_serializing_if = "Option::is_none")]
		build_info: &'a Option<BuildInfo>,
	}

impl BuildAttestation {
    fn signing_payload(&self) -> AttestationSigningPayload<'_> {
        AttestationSigningPayload {
            schema_version: &self.schema_version,
            attestation_id: &self.attestation_id,
            subject_path: &self.subject_path,
            subject_kind: &self.subject_kind,
            subject_sha256: &self.subject_sha256,
            bundle_manifest_id: &self.bundle_manifest_id,
            bundle_root_hash: &self.bundle_root_hash,
            build_fingerprint: &self.build_fingerprint,
            command: &self.command,
            timestamp_utc: &self.timestamp_utc,
            attested_by: &self.attested_by,
			signer_public_key: &self.signer_public_key,
			nonce: &self.nonce,
			build_info: &self.build_info,
		}
    }

    fn canonical_payload(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&self.signing_payload())?)
    }

	/// Verify nonce is at least the expected minimum
	pub fn verify_nonce(&self, expected: u64) -> bool {
		self.nonce.map(|n| n >= expected).unwrap_or(false)
	}

	/// Generate a SLSA Provenance v1.0 predicate from this attestation
	pub fn to_slsa_predicate(&self) -> serde_json::Value {
		let build_info = self.build_info.as_ref();
		serde_json::json!({
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [{
				"name": self.subject_path,
				"digest": {
					"sha256": self.subject_sha256,
				}
			}],
			"predicateType": "https://slsa.dev/provenance/v1",
			"predicate": {
				"buildDefinition": {
					"buildType": build_info.map(|b| b.build_type.clone()).unwrap_or_default(),
					"externalParameters": {},
					"internalParameters": {},
					"resolvedDependencies": build_info.map(|b| b.dependencies.iter().map(|d| serde_json::json!({
						"uri": format!("{}@{}", d.source, d.version),
						"digest": { "sha256": d.integrity }
					})).collect::<Vec<_>>()).unwrap_or_default(),
				},
				"runDetails": {
					"builder": {
						"id": build_info.map(|b| b.builder_id.clone()).unwrap_or_else(|| self.attested_by.clone()),
					},
					"metadata": {
						"invocationId": self.attestation_id,
						"startedOn": self.timestamp_utc.to_rfc3339(),
					}
				}
			}
		})
	}
}

pub fn create_build_attestation(
    subject_path: &Path,
    keypair: &KeyPair,
    options: AttestationOptions,
) -> Result<BuildAttestation> {
    let subject_kind = subject_kind(subject_path)?;
    let subject_sha256 = hash_subject(subject_path)?;
    let (bundle_manifest_id, bundle_root_hash) = match options.bundle_path.as_ref() {
        Some(bundle_path) => {
            let archive = MkpeArchive::load(bundle_path)?;
            archive.verify_artifact_with_public_key(subject_path, &keypair.public_key)?;
            (
                Some(archive.manifest.manifest_id),
                Some(archive.manifest.bundle_root_hash),
            )
        }
        None => (None, None),
    };

    let mut attestation = BuildAttestation {
        schema_version: ATTESTATION_SCHEMA_VERSION.to_string(),
        attestation_id: uuid::Uuid::new_v4().to_string(),
        subject_path: subject_path.display().to_string(),
        subject_kind,
        subject_sha256,
        bundle_manifest_id,
        bundle_root_hash,
		build_fingerprint: BuildFingerprint::capture(),
		build_info: None,
		command: options.command,
		timestamp_utc: chrono::Utc::now(),
		attested_by: options.attested_by,
		signer_public_key: keypair.public_key.clone(),
		signature: String::new(),
		nonce: Some(
			std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map(|d| d.as_nanos() as u64)
				.unwrap_or(0),
		),
	};

    attestation.signature = keypair.sign(&attestation.canonical_payload()?)?;
    Ok(attestation)
}

pub fn verify_build_attestation(
    attestation: &BuildAttestation,
    options: AttestationVerificationOptions,
) -> Result<AttestationVerificationReport> {
    if attestation.schema_version != ATTESTATION_SCHEMA_VERSION {
        return Err(MkpeError::VerificationFailed(format!(
            "Unsupported attestation schema version: {}",
            attestation.schema_version
        )));
    }

    if let Some(trusted_public_key) = options.trusted_public_key.as_ref() {
        if attestation.signer_public_key != trusted_public_key.trim() {
            return Err(MkpeError::VerificationFailed(
                "Attestation signer is not the expected trusted public key".to_string(),
            ));
        }
    }

    if !verify_signature(
        &attestation.signer_public_key,
        &attestation.canonical_payload()?,
        &attestation.signature,
    )? {
        return Err(MkpeError::VerificationFailed(
            "Attestation signature is invalid".to_string(),
        ));
    }

    if let Some(subject_path) = options.subject_path.as_ref() {
        let current_kind = subject_kind(subject_path)?;
        if current_kind != attestation.subject_kind {
            return Err(MkpeError::VerificationFailed(format!(
                "Subject kind mismatch: expected {:?}, got {:?}",
                attestation.subject_kind, current_kind
            )));
        }

        let current_hash = hash_subject(subject_path)?;
        if current_hash != attestation.subject_sha256 {
            return Err(MkpeError::VerificationFailed(format!(
                "Subject hash mismatch: expected {}, got {}",
                attestation.subject_sha256, current_hash
            )));
        }
    }

    verify_linked_bundle(
        attestation,
        options.bundle_path.as_deref(),
        options.subject_path.as_deref(),
    )?;

    Ok(AttestationVerificationReport {
        attestation_id: attestation.attestation_id.clone(),
        subject_sha256: attestation.subject_sha256.clone(),
        trusted_signer: options.trusted_public_key.is_some(),
        signer_public_key: attestation.signer_public_key.clone(),
        bundle_manifest_id: attestation.bundle_manifest_id.clone(),
        bundle_root_hash: attestation.bundle_root_hash.clone(),
    })
}

pub fn hash_subject(path: &Path) -> Result<String> {
    if path.is_file() {
        let bytes = std::fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        return Ok(hex::encode(hasher.finalize()));
    }

    if path.is_dir() {
        return hash_directory(path);
    }

    Err(MkpeError::VerificationFailed(format!(
        "Attestation subject does not exist: {}",
        path.display()
    )))
}

fn subject_kind(path: &Path) -> Result<AttestationSubjectKind> {
    if path.is_file() {
        return Ok(AttestationSubjectKind::File);
    }
    if path.is_dir() {
        return Ok(AttestationSubjectKind::Directory);
    }
    Err(MkpeError::VerificationFailed(format!(
        "Attestation subject does not exist: {}",
        path.display()
    )))
}

fn hash_directory(root: &Path) -> Result<String> {
    let mut entries = Vec::new();
    collect_directory_entries(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut hasher = Sha256::new();
    for (relative_path, file_hash) in entries {
        hasher.update(canonical_relative_path(&relative_path)?.as_bytes());
        hasher.update([0]);
        hasher.update(file_hash.as_bytes());
        hasher.update([0]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn collect_directory_entries(
    root: &Path,
    dir: &Path,
    entries: &mut Vec<(PathBuf, String)>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_directory_entries(root, &path, entries)?;
            continue;
        }
        let relative_path = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        entries.push((relative_path, hash_subject(&path)?));
    }
    Ok(())
}

fn canonical_relative_path(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            std::path::Component::CurDir => {}
            _ => {
                return Err(MkpeError::VerificationFailed(format!(
                    "Unsupported path component in attestation subject: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(parts.join("/"))
}

fn verify_linked_bundle(
    attestation: &BuildAttestation,
    bundle_path: Option<&Path>,
    subject_path: Option<&Path>,
) -> Result<()> {
    if attestation.bundle_manifest_id.is_none() && attestation.bundle_root_hash.is_none() {
        return Ok(());
    }

    let bundle_path = bundle_path.ok_or_else(|| {
        MkpeError::VerificationFailed(
            "Attestation links to a MKPE bundle, but no bundle path was provided".to_string(),
        )
    })?;
    let archive = MkpeArchive::load(bundle_path)?;

    let subject_path = subject_path.ok_or_else(|| {
        MkpeError::VerificationFailed(
            "Attestation links to a MKPE bundle, but no subject path was provided".to_string(),
        )
    })?;
    archive.verify_artifact_with_public_key(subject_path, &attestation.signer_public_key)?;

    if attestation.bundle_manifest_id.as_deref() != Some(archive.manifest.manifest_id.as_str()) {
        return Err(MkpeError::VerificationFailed(
            "Linked MKPE manifest ID does not match attestation".to_string(),
        ));
    }
    if attestation.bundle_root_hash.as_deref() != Some(archive.manifest.bundle_root_hash.as_str()) {
        return Err(MkpeError::VerificationFailed(
            "Linked MKPE root hash does not match attestation".to_string(),
        ));
    }

    Ok(())
}
