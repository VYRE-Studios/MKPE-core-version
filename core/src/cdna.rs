//! C-DNA (Component DNA) schema support
//!
//! Component DNA is the granular component identity system
//! that MKPE uses to establish provenance at the module level

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// C-DNA schema version
pub const CDNA_VERSION: &str = "3.0.0";

/// Complete C-DNA schema document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdnaSchema {
    /// C-DNA version
    pub c_dna_version: String,
    /// Unique program identifier
    pub program_id: String,
    /// High-level program purpose
    pub intent: String,
    /// Source information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_info: Option<SourceInfo>,
    /// Input definitions
    #[serde(default)]
    pub inputs: Vec<InputOutput>,
    /// Output definitions
    #[serde(default)]
    pub outputs: Vec<InputOutput>,
    /// Constraint list
    #[serde(default)]
    pub constraints: Vec<String>,
    /// Environment configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<HashMap<String, serde_json::Value>>,
    /// Validation rules
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<serde_json::Value>,
    /// Node definitions
    pub nodes: Vec<CdnaNode>,
    /// Edge connections
    #[serde(default)]
    pub edges: Vec<CdnaEdge>,
    /// Workflows (collections of edges)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflows: Option<Vec<Workflow>>,
    /// Performance metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub performance: Option<HashMap<String, serde_json::Value>>,
    /// Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Source information for clean-room extraction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    pub repository: String,
    pub language: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acquisition_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub translation_method: Option<String>,
}

/// Input/Output definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputOutput {
    pub name: String,
    #[serde(rename = "type")]
    pub io_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
}

/// Node in the C-DNA graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdnaNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Ports>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation: Option<Implementation>,
}

/// Port definitions for a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ports {
    #[serde(default)]
    pub inputs: Vec<Port>,
    #[serde(default)]
    pub outputs: Vec<Port>,
}

/// Individual port definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub name: String,
    #[serde(rename = "type")]
    pub port_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Implementation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Implementation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Edge connecting two nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdnaEdge {
    pub from: String,
    pub to: String,
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_port: Option<String>,
}

/// Workflow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub edges: Vec<CdnaEdge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<HashMap<String, HashMap<String, serde_json::Value>>>,
}

impl CdnaSchema {
    /// Create a new C-DNA schema
    pub fn new(program_id: String, intent: String) -> Self {
        Self {
            c_dna_version: CDNA_VERSION.to_string(),
            program_id,
            intent,
            source_info: None,
            inputs: Vec::new(),
            outputs: Vec::new(),
            constraints: Vec::new(),
            environment: None,
            validation: None,
            nodes: Vec::new(),
            edges: Vec::new(),
            workflows: None,
            performance: None,
            metadata: None,
        }
    }

    /// Load from JSON file
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let schema = serde_json::from_str(&content)?;
        Ok(schema)
    }

    /// Save to JSON file
    pub fn to_file<P: AsRef<std::path::Path>>(&self, path: P) -> crate::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Calculate hash of this C-DNA schema
    pub fn calculate_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        
        let json = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Create a proof for this C-DNA schema
    pub fn create_proof(&self, keypair: &crate::crypto::KeyPair) -> crate::Result<CdnaProof> {
        let schema_hash = self.calculate_hash();
        let proof_id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now();

        let proof_data = format!("{}:{}:{}", proof_id, schema_hash, timestamp);
        let signature = keypair.sign(proof_data.as_bytes())?;

        Ok(CdnaProof {
            proof_id,
            program_id: self.program_id.clone(),
            schema_hash,
            timestamp,
            signature,
            verifier_public_key: keypair.public_key.clone(),
        })
    }
}

/// Proof of a C-DNA schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdnaProof {
    pub proof_id: String,
    pub program_id: String,
    pub schema_hash: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub signature: String,
    pub verifier_public_key: String,
}

impl CdnaProof {
    /// Verify this proof
    pub fn verify(&self) -> crate::Result<bool> {
        let proof_data = format!("{}:{}:{}", self.proof_id, self.schema_hash, self.timestamp);
        crate::crypto::verify_signature(
            &self.verifier_public_key,
            proof_data.as_bytes(),
            &self.signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdna_schema_creation() {
        let schema = CdnaSchema::new(
            "test.program.v1".to_string(),
            "Test program for validation".to_string(),
        );

        assert_eq!(schema.c_dna_version, CDNA_VERSION);
        assert_eq!(schema.program_id, "test.program.v1");
    }

    #[test]
    fn test_cdna_hash() {
        let schema = CdnaSchema::new(
            "test.program.v1".to_string(),
            "Test program".to_string(),
        );

        let hash = schema.calculate_hash();
        assert_eq!(hash.len(), 64); // SHA-256 hex length
    }

    #[test]
    fn test_cdna_proof() -> crate::Result<()> {
        let keypair = crate::crypto::generate_keypair();
        let schema = CdnaSchema::new(
            "test.program.v1".to_string(),
            "Test program".to_string(),
        );

        let proof = schema.create_proof(&keypair)?;
        assert!(!proof.proof_id.is_empty());
        assert!(!proof.signature.is_empty());

        let is_valid = proof.verify()?;
        assert!(is_valid);

        Ok(())
    }
}



