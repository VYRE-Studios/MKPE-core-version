//! Condition registry and policy deserialization.
//!
//! The registry maps condition type names (e.g. `"key_version"`, `"bundle_hash"`)
//! to constructor functions. Policy JSON files reference conditions by type name,
//! and the registry resolves them to concrete condition instances.

use crate::policy_v2::conditions::*;
use crate::policy_v2::PolicyError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// A factory function that deserializes JSON parameters into a boxed condition.
type ConditionFactory = fn(&Value) -> Result<Box<dyn PolicyCondition>, PolicyError>;

/// Registry mapping condition type names to their deserializing constructors.
#[derive(Clone)]
pub struct ConditionRegistry {
    factories: BTreeMap<String, ConditionFactory>,
}

impl ConditionRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            factories: BTreeMap::new(),
        }
    }

    /// Create a registry pre-loaded with all built-in conditions.
    pub fn with_builtins() -> Self {
        let mut reg = Self::new();
        reg.register("key_version", deserialize_key_version);
        reg.register("timestamp_range", deserialize_timestamp_range);
        reg.register("timestamp_freshness", deserialize_timestamp_freshness);
        reg.register("key_id", deserialize_key_id);
        reg.register("trusted_key", deserialize_trusted_key);
        reg.register("chain_depth", deserialize_chain_depth);
        reg.register("bundle_hash", deserialize_bundle_hash);
        reg.register("nonce_fresh", deserialize_nonce_fresh);
        reg.register("schema_version", deserialize_schema_version);
        reg.register("metadata_field", deserialize_metadata_field);
        reg
    }

    /// Register a condition type by name.
    pub fn register(&mut self, name: &str, factory: ConditionFactory) {
        self.factories.insert(name.to_string(), factory);
    }

    /// Deserialize a condition from a type name and parameters.
    pub fn deserialize(
        &self,
        type_name: &str,
        params: &Value,
    ) -> Result<Box<dyn PolicyCondition>, PolicyError> {
        match self.factories.get(type_name) {
            Some(factory) => factory(params),
            None => Err(PolicyError::UnknownConditionType(type_name.to_string())),
        }
    }

    /// List all registered condition type names.
    pub fn registered_types(&self) -> Vec<&str> {
        self.factories.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for ConditionRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

// ---------------------------------------------------------------------------
// JSON condition descriptor (used in policy files)
// ---------------------------------------------------------------------------

/// A condition entry in a policy file: `"type"` + `"params"`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConditionDescriptor {
    /// Condition type name, e.g. `"key_version"`.
    #[serde(rename = "type")]
    pub type_name: String,
    /// Parameters for the condition, parsed by the registry.
    #[serde(default)]
    pub params: Value,
}

// ---------------------------------------------------------------------------
// Policy file format
// ---------------------------------------------------------------------------

/// A serializable policy definition as it appears in JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyDefinition {
    /// Human-readable policy name.
    pub name: String,
    /// How to combine condition results: `"all"` or `"any"`.
    #[serde(default = "default_combine_mode_str")]
    pub combine: String,
    /// Severity: `"info"`, `"warning"`, or `"critical"`.
    #[serde(default = "default_severity_str")]
    pub severity: String,
    /// Conditions to evaluate.
    pub conditions: Vec<ConditionDescriptor>,
}

fn default_combine_mode_str() -> String {
    "all".to_string()
}
fn default_severity_str() -> String {
    "warning".to_string()
}

/// A full policy file: list of policy definitions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyFile {
    pub policies: Vec<PolicyDefinition>,
}

// ---------------------------------------------------------------------------
// Deserialization helpers for built-in conditions
// ---------------------------------------------------------------------------

fn deserialize_key_version(params: &Value) -> Result<Box<dyn PolicyCondition>, PolicyError> {
    let min = params
        .get("min")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| PolicyError::InvalidParameters("key_version requires 'min' (u32)".into()))?
        as u32;
    Ok(Box::new(KeyVersionCondition { min }))
}

fn deserialize_timestamp_range(params: &Value) -> Result<Box<dyn PolicyCondition>, PolicyError> {
    let min = params
        .get("min")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PolicyError::InvalidParameters(
                "timestamp_range requires 'min' (ISO 8601 datetime string)".into(),
            )
        })?
        .parse::<DateTime<Utc>>()
        .map_err(|e| PolicyError::InvalidParameters(format!("Invalid min datetime: {}", e)))?;
    let max = params
        .get("max")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PolicyError::InvalidParameters(
                "timestamp_range requires 'max' (ISO 8601 datetime string)".into(),
            )
        })?
        .parse::<DateTime<Utc>>()
        .map_err(|e| PolicyError::InvalidParameters(format!("Invalid max datetime: {}", e)))?;
    Ok(Box::new(TimestampRangeCondition { min, max }))
}

fn deserialize_timestamp_freshness(
    params: &Value,
) -> Result<Box<dyn PolicyCondition>, PolicyError> {
    let max_age_seconds = params
        .get("max_age_seconds")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| {
            PolicyError::InvalidParameters(
                "timestamp_freshness requires 'max_age_seconds' (i64)".into(),
            )
        })?;
    Ok(Box::new(TimestampFreshnessCondition { max_age_seconds }))
}

fn deserialize_key_id(params: &Value) -> Result<Box<dyn PolicyCondition>, PolicyError> {
    let allowed = params
        .get("allowed")
        .and_then(|v| v.as_array())
        .ok_or_else(|| PolicyError::InvalidParameters("key_id requires 'allowed' array".into()))?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    Ok(Box::new(KeyIdCondition { allowed }))
}

fn deserialize_trusted_key(_params: &Value) -> Result<Box<dyn PolicyCondition>, PolicyError> {
    Ok(Box::new(TrustedKeyCondition {}))
}

fn deserialize_chain_depth(params: &Value) -> Result<Box<dyn PolicyCondition>, PolicyError> {
    let min = params
        .get("min")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            PolicyError::InvalidParameters("chain_depth requires 'min' (u32)".into())
        })? as u32;
    Ok(Box::new(ChainDepthCondition { min }))
}

fn deserialize_bundle_hash(params: &Value) -> Result<Box<dyn PolicyCondition>, PolicyError> {
    let expected = params
        .get("expected")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PolicyError::InvalidParameters("bundle_hash requires 'expected' string".into())
        })?
        .to_string();
    Ok(Box::new(BundleHashCondition { expected }))
}

fn deserialize_nonce_fresh(params: &Value) -> Result<Box<dyn PolicyCondition>, PolicyError> {
    let min_nonce = params
        .get("min_nonce")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            PolicyError::InvalidParameters("nonce_fresh requires 'min_nonce' (u64)".into())
        })?;
    Ok(Box::new(NonceFreshCondition { min_nonce }))
}

fn deserialize_schema_version(params: &Value) -> Result<Box<dyn PolicyCondition>, PolicyError> {
    let expected = params
        .get("expected")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PolicyError::InvalidParameters("schema_version requires 'expected' string".into())
        })?
        .to_string();
    Ok(Box::new(SchemaVersionCondition { expected }))
}

fn deserialize_metadata_field(params: &Value) -> Result<Box<dyn PolicyCondition>, PolicyError> {
    let key = params
        .get("key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PolicyError::InvalidParameters("metadata_field requires 'key' string".into())
        })?
        .to_string();
    let expected_value = params.get("expected_value").cloned();
    Ok(Box::new(MetadataFieldCondition {
        key,
        expected_value,
    }))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;

    fn test_manifest() -> Manifest {
        let mut m = Manifest::new(
            "abc123".to_string(),
            3,
            "pk_test".to_string(),
            None,
        );
        m.engine_version = "2.0.0".to_string();
        m
    }

    #[test]
    fn test_registry_has_all_builtins() {
        let reg = ConditionRegistry::with_builtins();
        let types = reg.registered_types();
        assert!(types.contains(&"key_version"));
        assert!(types.contains(&"timestamp_range"));
        assert!(types.contains(&"timestamp_freshness"));
        assert!(types.contains(&"key_id"));
        assert!(types.contains(&"trusted_key"));
        assert!(types.contains(&"chain_depth"));
        assert!(types.contains(&"bundle_hash"));
        assert!(types.contains(&"nonce_fresh"));
        assert!(types.contains(&"schema_version"));
        assert!(types.contains(&"metadata_field"));
    }

    #[test]
    fn test_registry_rejects_unknown_type() {
        let reg = ConditionRegistry::new();
        let result = reg.deserialize("unknown_type", &Value::Null);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_key_version() {
        let reg = ConditionRegistry::with_builtins();
        let cond = reg
            .deserialize("key_version", &serde_json::json!({"min": 2}))
            .unwrap();
        assert_eq!(cond.name(), "key_version");

        let m = test_manifest();
        let ctx = crate::policy_v2::PolicyContext::new(&m);
        assert!(cond.evaluate(&ctx).is_pass());
    }

    #[test]
    fn test_deserialize_bundle_hash() {
        let reg = ConditionRegistry::with_builtins();
        let cond = reg
            .deserialize("bundle_hash", &serde_json::json!({"expected": "abc123"}))
            .unwrap();
        assert_eq!(cond.name(), "bundle_hash");

        let m = test_manifest();
        let ctx = crate::policy_v2::PolicyContext::new(&m);
        assert!(cond.evaluate(&ctx).is_pass());
    }

    #[test]
    fn test_deserialize_key_id() {
        let reg = ConditionRegistry::with_builtins();
        let cond = reg
            .deserialize(
                "key_id",
                &serde_json::json!({"allowed": ["pk_test", "pk_other"]}),
            )
            .unwrap();
        assert_eq!(cond.name(), "key_id");

        let m = test_manifest();
        let ctx = crate::policy_v2::PolicyContext::new(&m);
        assert!(cond.evaluate(&ctx).is_pass());
    }

    #[test]
    fn test_policy_file_round_trip() {
        let policy_file = PolicyFile {
            policies: vec![PolicyDefinition {
                name: "test_policy".to_string(),
                combine: "all".to_string(),
                severity: "critical".to_string(),
                conditions: vec![
                    ConditionDescriptor {
                        type_name: "bundle_hash".to_string(),
                        params: serde_json::json!({"expected": "abc123"}),
                    },
                    ConditionDescriptor {
                        type_name: "key_id".to_string(),
                        params: serde_json::json!({"allowed": ["pk_test"]}),
                    },
                ],
            }],
        };

        let json = serde_json::to_string_pretty(&policy_file).unwrap();
        let parsed: PolicyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, policy_file);
    }
}