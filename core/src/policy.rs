//! Policy engine for manifest verification
//!
//! Defines declarative policies that constrain manifest fields,
//! timestamps, chain depth, and freshness nonces. Policies are
//! evaluated against `Manifest` instances by a `PolicyEngine`.

use crate::{manifest::Manifest, MkpeError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A single condition evaluated against a manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyCondition {
    /// Minimum major engine version (parsed from `Manifest::engine_version`).
    KeyVersion { min: u32 },
    /// Manifest sealed timestamp must fall within the inclusive range.
    TimestampRange { min: DateTime<Utc>, max: DateTime<Utc> },
    /// Public key must be in the allowed list.
    KeyId { allowed: Vec<String> },
    /// Minimum chain depth. Depth is read from metadata `"chain_depth"` if
    /// present; otherwise inferred as `1` without a parent, `2` with one.
    ChainDepth { min: u32 },
    /// Bundle root hash must exactly match.
    BundleHash { expected: String },
    /// Metadata nonce must exist and be >= `min_nonce`.
    NonceFresh { min_nonce: u64 },
}

impl PolicyCondition {
    fn evaluate(&self, manifest: &Manifest) -> bool {
        match self {
            PolicyCondition::KeyVersion { min } => {
                parse_major_version(&manifest.engine_version).map_or(false, |v| v >= *min)
            }
            PolicyCondition::TimestampRange { min, max } => {
                manifest.sealed_timestamp >= *min && manifest.sealed_timestamp <= *max
            }
            PolicyCondition::KeyId { allowed } => allowed.contains(&manifest.verifier_public_key),
            PolicyCondition::ChainDepth { min } => {
                let depth = manifest
                    .metadata
                    .get("chain_depth")
                    .and_then(|v| v.as_u64())
                    .map(|d| d as u32)
                    .or_else(|| {
                        if manifest.parent_manifest_id.is_some() {
                            Some(2)
                        } else {
                            Some(1)
                        }
                    })
                    .unwrap_or(1);
                depth >= *min
            }
            PolicyCondition::BundleHash { expected } => {
                manifest.bundle_root_hash == *expected
            }
            PolicyCondition::NonceFresh { min_nonce } => manifest
                .metadata
                .get("nonce")
                .and_then(|v| v.as_u64())
                .map_or(false, |nonce| nonce >= *min_nonce),
        }
    }
}

/// Named collection of conditions with a boolean combining operator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Policy {
    pub name: String,
    pub conditions: Vec<PolicyCondition>,
    pub require_all: bool,
}

impl Policy {
    /// Evaluate this policy against a manifest.
    ///
    /// * `require_all == true` — every condition must pass (AND).
    /// * `require_all == false` — at least one condition must pass (OR).
    ///
    /// An empty condition list is treated as vacuously true.
    pub fn evaluate(&self, manifest: &Manifest) -> bool {
        if self.conditions.is_empty() {
            return true;
        }
        if self.require_all {
            self.conditions.iter().all(|c| c.evaluate(manifest))
        } else {
            self.conditions.iter().any(|c| c.evaluate(manifest))
        }
    }
}

/// Container for all active policies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyEngine {
    pub policies: Vec<Policy>,
}

impl PolicyEngine {
    /// Verify that every loaded policy evaluates to `true` for the given manifest.
    ///
    /// Returns `Ok(false)` as soon as any policy fails; `Ok(true)` when all pass.
    /// An empty policy set is vacuously true.
    pub fn verify(&self, manifest: &Manifest) -> Result<bool> {
        for policy in &self.policies {
            if !policy.evaluate(manifest) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Load a policy engine from a JSON file on disk.
    pub fn load_from_json(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(MkpeError::IoError)?;
        let engine: PolicyEngine = serde_json::from_str(&contents).map_err(MkpeError::JsonError)?;
        Ok(engine)
    }
}

/// Extract the leading numeric component from a dotted version string.
fn parse_major_version(version: &str) -> Option<u32> {
    version.split('.').next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;
    use chrono::{Duration, Utc};

    fn test_manifest() -> Manifest {
        Manifest::new(
            "abc123".to_string(),
            3,
            "pk_test".to_string(),
            None,
        )
    }

    // ------------------------------------------------------------------
    // KeyVersion
    // ------------------------------------------------------------------

    #[test]
    fn test_key_version_passes_when_above_min() {
        let mut m = test_manifest();
        m.engine_version = "2.0.0".to_string();
        let cond = PolicyCondition::KeyVersion { min: 1 };
        assert!(cond.evaluate(&m));
        let cond = PolicyCondition::KeyVersion { min: 2 };
        assert!(cond.evaluate(&m));
    }

    #[test]
    fn test_key_version_fails_when_below_min() {
        let mut m = test_manifest();
        m.engine_version = "1.0.0".to_string();
        let cond = PolicyCondition::KeyVersion { min: 2 };
        assert!(!cond.evaluate(&m));
    }

    #[test]
    fn test_key_version_rejects_invalid_format() {
        let mut m = test_manifest();
        m.engine_version = "invalid".to_string();
        let cond = PolicyCondition::KeyVersion { min: 1 };
        assert!(!cond.evaluate(&m));
    }

    // ------------------------------------------------------------------
    // TimestampRange
    // ------------------------------------------------------------------

    #[test]
    fn test_timestamp_range_passes_when_inside() {
        let mut m = test_manifest();
        let now = Utc::now();
        m.sealed_timestamp = now;
        let cond = PolicyCondition::TimestampRange {
            min: now - Duration::hours(1),
            max: now + Duration::hours(1),
        };
        assert!(cond.evaluate(&m));
    }

    #[test]
    fn test_timestamp_range_fails_when_before_min() {
        let mut m = test_manifest();
        let now = Utc::now();
        m.sealed_timestamp = now - Duration::hours(2);
        let cond = PolicyCondition::TimestampRange {
            min: now - Duration::hours(1),
            max: now + Duration::hours(1),
        };
        assert!(!cond.evaluate(&m));
    }

    #[test]
    fn test_timestamp_range_fails_when_after_max() {
        let mut m = test_manifest();
        let now = Utc::now();
        m.sealed_timestamp = now + Duration::hours(2);
        let cond = PolicyCondition::TimestampRange {
            min: now - Duration::hours(1),
            max: now + Duration::hours(1),
        };
        assert!(!cond.evaluate(&m));
    }

    #[test]
    fn test_timestamp_range_inclusive_bounds() {
        let mut m = test_manifest();
        let now = Utc::now();
        m.sealed_timestamp = now;
        let cond = PolicyCondition::TimestampRange {
            min: now,
            max: now,
        };
        assert!(cond.evaluate(&m));
    }

    // ------------------------------------------------------------------
    // KeyId
    // ------------------------------------------------------------------

    #[test]
    fn test_key_id_passes_when_in_allowed_list() {
        let m = test_manifest();
        let cond = PolicyCondition::KeyId {
            allowed: vec!["pk_test".to_string(), "other".to_string()],
        };
        assert!(cond.evaluate(&m));
    }

    #[test]
    fn test_key_id_fails_when_not_in_allowed_list() {
        let m = test_manifest();
        let cond = PolicyCondition::KeyId {
            allowed: vec!["other".to_string()],
        };
        assert!(!cond.evaluate(&m));
    }

    // ------------------------------------------------------------------
    // ChainDepth
    // ------------------------------------------------------------------

    #[test]
    fn test_chain_depth_no_parent_min_one_passes() {
        let m = test_manifest(); // parent_manifest_id == None
        let cond = PolicyCondition::ChainDepth { min: 1 };
        assert!(cond.evaluate(&m));
    }

    #[test]
    fn test_chain_depth_no_parent_min_two_fails() {
        let m = test_manifest();
        let cond = PolicyCondition::ChainDepth { min: 2 };
        assert!(!cond.evaluate(&m));
    }

    #[test]
    fn test_chain_depth_with_parent_min_two_passes() {
        let mut m = test_manifest();
        m.parent_manifest_id = Some("parent123".to_string());
        let cond = PolicyCondition::ChainDepth { min: 2 };
        assert!(cond.evaluate(&m));
    }

    #[test]
    fn test_chain_depth_with_parent_min_three_fails_without_metadata() {
        let mut m = test_manifest();
        m.parent_manifest_id = Some("parent123".to_string());
        let cond = PolicyCondition::ChainDepth { min: 3 };
        assert!(!cond.evaluate(&m));
    }

    #[test]
    fn test_chain_depth_from_metadata() {
        let mut m = test_manifest();
        m.metadata
            .insert("chain_depth".to_string(), serde_json::json!(5u64));
        let cond = PolicyCondition::ChainDepth { min: 5 };
        assert!(cond.evaluate(&m));
        let cond = PolicyCondition::ChainDepth { min: 6 };
        assert!(!cond.evaluate(&m));
    }

    // ------------------------------------------------------------------
    // BundleHash
    // ------------------------------------------------------------------

    #[test]
    fn test_bundle_hash_passes_when_equal() {
        let m = test_manifest(); // bundle_root_hash == "abc123"
        let cond = PolicyCondition::BundleHash {
            expected: "abc123".to_string(),
        };
        assert!(cond.evaluate(&m));
    }

    #[test]
    fn test_bundle_hash_fails_when_mismatched() {
        let m = test_manifest();
        let cond = PolicyCondition::BundleHash {
            expected: "wrong".to_string(),
        };
        assert!(!cond.evaluate(&m));
    }

    // ------------------------------------------------------------------
    // NonceFresh
    // ------------------------------------------------------------------

    #[test]
    fn test_nonce_fresh_passes_when_above_min() {
        let mut m = test_manifest();
        m.metadata
            .insert("nonce".to_string(), serde_json::json!(100u64));
        let cond = PolicyCondition::NonceFresh { min_nonce: 50 };
        assert!(cond.evaluate(&m));
    }

    #[test]
    fn test_nonce_fresh_fails_when_below_min() {
        let mut m = test_manifest();
        m.metadata
            .insert("nonce".to_string(), serde_json::json!(10u64));
        let cond = PolicyCondition::NonceFresh { min_nonce: 50 };
        assert!(!cond.evaluate(&m));
    }

    #[test]
    fn test_nonce_fresh_fails_when_missing() {
        let m = test_manifest();
        let cond = PolicyCondition::NonceFresh { min_nonce: 1 };
        assert!(!cond.evaluate(&m));
    }

    // ------------------------------------------------------------------
    // Policy (combined conditions)
    // ------------------------------------------------------------------

    #[test]
    fn test_policy_require_all_passes_when_all_match() {
        let m = test_manifest();
        let policy = Policy {
            name: "test".to_string(),
            conditions: vec![
                PolicyCondition::BundleHash {
                    expected: "abc123".to_string(),
                },
                PolicyCondition::KeyId {
                    allowed: vec!["pk_test".to_string()],
                },
            ],
            require_all: true,
        };
        assert!(policy.evaluate(&m));
    }

    #[test]
    fn test_policy_require_all_fails_when_one_mismatches() {
        let m = test_manifest();
        let policy = Policy {
            name: "test".to_string(),
            conditions: vec![
                PolicyCondition::BundleHash {
                    expected: "abc123".to_string(),
                },
                PolicyCondition::KeyId {
                    allowed: vec!["wrong".to_string()],
                },
            ],
            require_all: true,
        };
        assert!(!policy.evaluate(&m));
    }

    #[test]
    fn test_policy_require_any_passes_when_one_matches() {
        let m = test_manifest();
        let policy = Policy {
            name: "test".to_string(),
            conditions: vec![
                PolicyCondition::BundleHash {
                    expected: "wrong".to_string(),
                },
                PolicyCondition::KeyId {
                    allowed: vec!["pk_test".to_string()],
                },
            ],
            require_all: false,
        };
        assert!(policy.evaluate(&m));
    }

    #[test]
    fn test_policy_require_any_fails_when_none_match() {
        let m = test_manifest();
        let policy = Policy {
            name: "test".to_string(),
            conditions: vec![
                PolicyCondition::BundleHash {
                    expected: "wrong".to_string(),
                },
                PolicyCondition::KeyId {
                    allowed: vec!["wrong".to_string()],
                },
            ],
            require_all: false,
        };
        assert!(!policy.evaluate(&m));
    }

    #[test]
    fn test_policy_empty_conditions_vacuously_true() {
        let m = test_manifest();
        let policy = Policy {
            name: "empty".to_string(),
            conditions: vec![],
            require_all: true,
        };
        assert!(policy.evaluate(&m));
    }

    // ------------------------------------------------------------------
    // PolicyEngine
    // ------------------------------------------------------------------

    #[test]
    fn test_engine_verify_passes_when_all_policies_match() {
        let m = test_manifest();
        let engine = PolicyEngine {
            policies: vec![
                Policy {
                    name: "p1".to_string(),
                    conditions: vec![PolicyCondition::BundleHash {
                        expected: "abc123".to_string(),
                    }],
                    require_all: true,
                },
                Policy {
                    name: "p2".to_string(),
                    conditions: vec![PolicyCondition::KeyId {
                        allowed: vec!["pk_test".to_string()],
                    }],
                    require_all: true,
                },
            ],
        };
        assert!(engine.verify(&m).unwrap());
    }

    #[test]
    fn test_engine_verify_fails_when_any_policy_fails() {
        let m = test_manifest();
        let engine = PolicyEngine {
            policies: vec![
                Policy {
                    name: "p1".to_string(),
                    conditions: vec![PolicyCondition::BundleHash {
                        expected: "wrong".to_string(),
                    }],
                    require_all: true,
                },
            ],
        };
        assert_eq!(engine.verify(&m).unwrap(), false);
    }

    #[test]
    fn test_engine_empty_policies_vacuously_true() {
        let m = test_manifest();
        let engine = PolicyEngine { policies: vec![] };
        assert!(engine.verify(&m).unwrap());
    }

    #[test]
    fn test_engine_load_from_json_round_trip() {
        let engine = PolicyEngine {
            policies: vec![
                Policy {
                    name: "loaded".to_string(),
                    conditions: vec![PolicyCondition::BundleHash {
                        expected: "hash".to_string(),
                    }],
                    require_all: true,
                },
            ],
        };
        let json = serde_json::to_string(&engine).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(&path, &json).unwrap();
        let loaded = PolicyEngine::load_from_json(&path).unwrap();
        assert_eq!(loaded, engine);
    }

    #[test]
    fn test_engine_load_from_json_rejects_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, b"not json").unwrap();
        let result = PolicyEngine::load_from_json(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_engine_load_from_json_rejects_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let result = PolicyEngine::load_from_json(&path);
        assert!(result.is_err());
    }
}
