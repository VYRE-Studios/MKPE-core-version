//! Built-in condition implementations.
//!
//! Each condition is a named, serializable type that implements PolicyCondition.
//! They mirror the v1 PolicyCondition enum variants but as separate struct types
//! that are individually testable, extensible, and deserializable from JSON.

use crate::policy_v2::{ConditionResult, PolicyContext};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// A single evaluation condition that can pass, fail, or be skipped.
///
/// Implementations must be `Send + Sync` so they can live in a registry
/// and be `Clone`-able for JSON round-trips.
pub trait PolicyCondition: Send + Sync + fmt::Debug {
    /// Human-readable name of this condition.
    fn name(&self) -> &str;

    /// Evaluate this condition against the given context.
    fn evaluate(&self, ctx: &PolicyContext<'_>) -> ConditionResult;

    /// Clone into a boxed trait object.
    fn clone_box(&self) -> Box<dyn PolicyCondition>;
}

/// Required for registry storage.
impl Clone for Box<dyn PolicyCondition> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

// ---------------------------------------------------------------------------
// KeyVersion — minimum engine version
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyVersionCondition {
    pub min: u32,
}

impl PolicyCondition for KeyVersionCondition {
    fn name(&self) -> &str {
        "key_version"
    }

    fn evaluate(&self, ctx: &PolicyContext<'_>) -> ConditionResult {
        match parse_major_version(&ctx.manifest.engine_version) {
            Some(v) if v >= self.min => ConditionResult::Pass,
            Some(v) => ConditionResult::Fail {
                reason: format!(
                    "Engine version {} is below minimum {}",
                    &ctx.manifest.engine_version, self.min
                ),
                code: "key_version_below_min".to_string(),
            },
            None => ConditionResult::Fail {
                reason: format!(
                    "Cannot parse engine version '{}'",
                    &ctx.manifest.engine_version
                ),
                code: "key_version_invalid".to_string(),
            },
        }
    }

    fn clone_box(&self) -> Box<dyn PolicyCondition> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// TimestampRange — sealed timestamp must fall within [min, max]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimestampRangeCondition {
    pub min: DateTime<Utc>,
    pub max: DateTime<Utc>,
}

impl PolicyCondition for TimestampRangeCondition {
    fn name(&self) -> &str {
        "timestamp_range"
    }

    fn evaluate(&self, ctx: &PolicyContext<'_>) -> ConditionResult {
        let ts = ctx.manifest.sealed_timestamp;
        if ts >= self.min && ts <= self.max {
            ConditionResult::Pass
        } else {
            ConditionResult::Fail {
                reason: format!(
                    "Sealed timestamp {} is outside range [{}, {}]",
                    ts, self.min, self.max
                ),
                code: "timestamp_out_of_range".to_string(),
            }
        }
    }

    fn clone_box(&self) -> Box<dyn PolicyCondition> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// TimestampFreshness — sealed timestamp must be within N seconds of "now"
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimestampFreshnessCondition {
    /// Maximum allowed age in seconds.
    pub max_age_seconds: i64,
}

impl PolicyCondition for TimestampFreshnessCondition {
    fn name(&self) -> &str {
        "timestamp_freshness"
    }

    fn evaluate(&self, ctx: &PolicyContext<'_>) -> ConditionResult {
        let now = ctx.now();
        let ts = ctx.manifest.sealed_timestamp;
        let age = now.signed_duration_since(ts);
        if age.num_seconds() <= self.max_age_seconds && age.num_seconds() >= 0 {
            ConditionResult::Pass
        } else {
            ConditionResult::Fail {
                reason: format!(
                    "Manifest age {}s exceeds max {}s",
                    age.num_seconds(),
                    self.max_age_seconds
                ),
                code: "timestamp_stale".to_string(),
            }
        }
    }

    fn clone_box(&self) -> Box<dyn PolicyCondition> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// KeyId — public key must be in the allowed list
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyIdCondition {
    pub allowed: Vec<String>,
}

impl PolicyCondition for KeyIdCondition {
    fn name(&self) -> &str {
        "key_id"
    }

    fn evaluate(&self, ctx: &PolicyContext<'_>) -> ConditionResult {
        if self.allowed.contains(&ctx.manifest.verifier_public_key) {
            ConditionResult::Pass
        } else {
            ConditionResult::Fail {
                reason: format!(
                    "Key '{}' is not in the allowed list",
                    &ctx.manifest.verifier_public_key
                ),
                code: "key_id_not_allowed".to_string(),
            }
        }
    }

    fn clone_box(&self) -> Box<dyn PolicyCondition> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// TrustedKey — key must be in trusted_keys context AND not revoked
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustedKeyCondition {}

impl PolicyCondition for TrustedKeyCondition {
    fn name(&self) -> &str {
        "trusted_key"
    }

    fn evaluate(&self, ctx: &PolicyContext<'_>) -> ConditionResult {
        let key = &ctx.manifest.verifier_public_key;
        if ctx.trusted_keys.is_empty() {
            return ConditionResult::Skip {
                reason: "No trusted keys configured — skipping".to_string(),
            };
        }

        // Check for a matching key_id first, then raw public key.
        let found = ctx
            .trusted_keys
            .values()
            .any(|v| v == key)
            || ctx.trusted_keys.contains_key(key);

        if !found {
            return ConditionResult::Fail {
                reason: format!("Key '{}' is not in the trusted set", key),
                code: "key_not_trusted".to_string(),
            };
        }

        if ctx.revoked_keys.contains(key) {
            return ConditionResult::Fail {
                reason: format!("Key '{}' is revoked", key),
                code: "key_revoked".to_string(),
            };
        }

        ConditionResult::Pass
    }

    fn clone_box(&self) -> Box<dyn PolicyCondition> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// ChainDepth — minimum chain depth
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChainDepthCondition {
    pub min: u32,
}

impl PolicyCondition for ChainDepthCondition {
    fn name(&self) -> &str {
        "chain_depth"
    }

    fn evaluate(&self, ctx: &PolicyContext<'_>) -> ConditionResult {
        let depth = ctx.manifest.chain_depth();
        if depth >= self.min {
            ConditionResult::Pass
        } else {
            ConditionResult::Fail {
                reason: format!(
                    "Chain depth {} is below minimum {}",
                    depth, self.min
                ),
                code: "chain_depth_below_min".to_string(),
            }
        }
    }

    fn clone_box(&self) -> Box<dyn PolicyCondition> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// BundleHash — bundle root hash must exactly match
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BundleHashCondition {
    pub expected: String,
}

impl PolicyCondition for BundleHashCondition {
    fn name(&self) -> &str {
        "bundle_hash"
    }

    fn evaluate(&self, ctx: &PolicyContext<'_>) -> ConditionResult {
        if ctx.manifest.bundle_root_hash == self.expected {
            ConditionResult::Pass
        } else {
            ConditionResult::Fail {
                reason: format!(
                    "Bundle hash '{}' does not match expected '{}'",
                    &ctx.manifest.bundle_root_hash, &self.expected
                ),
                code: "bundle_hash_mismatch".to_string(),
            }
        }
    }

    fn clone_box(&self) -> Box<dyn PolicyCondition> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// NonceFresh — metadata nonce must be >= min_nonce
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NonceFreshCondition {
    pub min_nonce: u64,
}

impl PolicyCondition for NonceFreshCondition {
    fn name(&self) -> &str {
        "nonce_fresh"
    }

    fn evaluate(&self, ctx: &PolicyContext<'_>) -> ConditionResult {
        match ctx
            .manifest
            .metadata
            .get("nonce")
            .and_then(|v| v.as_u64())
        {
            Some(nonce) if nonce >= self.min_nonce => ConditionResult::Pass,
            Some(nonce) => ConditionResult::Fail {
                reason: format!(
                    "Nonce {} is below minimum {}",
                    nonce, self.min_nonce
                ),
                code: "nonce_below_min".to_string(),
            },
            None => ConditionResult::Fail {
                reason: "Manifest metadata has no 'nonce' field".to_string(),
                code: "nonce_missing".to_string(),
            },
        }
    }

    fn clone_box(&self) -> Box<dyn PolicyCondition> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// SchemaVersion — manifest schema version must match
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemaVersionCondition {
    pub expected: String,
}

impl PolicyCondition for SchemaVersionCondition {
    fn name(&self) -> &str {
        "schema_version"
    }

    fn evaluate(&self, ctx: &PolicyContext<'_>) -> ConditionResult {
        if ctx.manifest.schema_version == self.expected {
            ConditionResult::Pass
        } else {
            ConditionResult::Fail {
                reason: format!(
                    "Schema version '{}' does not match expected '{}'",
                    &ctx.manifest.schema_version, &self.expected
                ),
                code: "schema_version_mismatch".to_string(),
            }
        }
    }

    fn clone_box(&self) -> Box<dyn PolicyCondition> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// MetadataField — manifest must contain a metadata key with a matching value
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetadataFieldCondition {
    pub key: String,
    /// If `None`, just checks that the key exists.
    pub expected_value: Option<serde_json::Value>,
}

impl PolicyCondition for MetadataFieldCondition {
    fn name(&self) -> &str {
        "metadata_field"
    }

    fn evaluate(&self, ctx: &PolicyContext<'_>) -> ConditionResult {
        match ctx.manifest.metadata.get(&self.key) {
            Some(value) => match &self.expected_value {
                None => ConditionResult::Pass,
                Some(expected) => {
                    if value == expected {
                        ConditionResult::Pass
                    } else {
                        ConditionResult::Fail {
                            reason: format!(
                                "Metadata '{}' = {:?}, expected {:?}",
                                &self.key, value, expected
                            ),
                            code: "metadata_field_mismatch".to_string(),
                        }
                    }
                }
            },
            None => ConditionResult::Fail {
                reason: format!("Metadata key '{}' not found", &self.key),
                code: "metadata_field_missing".to_string(),
            },
        }
    }

    fn clone_box(&self) -> Box<dyn PolicyCondition> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// Helper: parse major version from dotted string
// ---------------------------------------------------------------------------

pub(crate) fn parse_major_version(version: &str) -> Option<u32> {
    version.split('.').next()?.parse().ok()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;
    use chrono::Duration;

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

    fn ctx(manifest: &Manifest) -> PolicyContext<'_> {
        PolicyContext::new(manifest)
    }

    // -- KeyVersionCondition --

    #[test]
    fn test_key_version_passes_when_at_min() {
        let m = test_manifest();
        let cond = KeyVersionCondition { min: 2 };
        assert!(cond.evaluate(&ctx(&m)).is_pass());
    }

    #[test]
    fn test_key_version_passes_when_above_min() {
        let m = test_manifest();
        let cond = KeyVersionCondition { min: 1 };
        assert!(cond.evaluate(&ctx(&m)).is_pass());
    }

    #[test]
    fn test_key_version_fails_when_below_min() {
        let m = test_manifest();
        let cond = KeyVersionCondition { min: 3 };
        let result = cond.evaluate(&ctx(&m));
        assert!(result.is_fail());
    }

    #[test]
    fn test_key_version_fails_on_invalid_format() {
        let mut m = test_manifest();
        m.engine_version = "not-a-version".to_string();
        let cond = KeyVersionCondition { min: 1 };
        let result = cond.evaluate(&ctx(&m));
        assert!(result.is_fail());
        assert!(result.is_fail());
    }

    // -- TimestampRangeCondition --

    #[test]
    fn test_timestamp_range_passes_when_inside() {
        let mut m = test_manifest();
        let now = Utc::now();
        m.sealed_timestamp = now;
        let cond = TimestampRangeCondition {
            min: now - Duration::hours(1),
            max: now + Duration::hours(1),
        };
        assert!(cond.evaluate(&ctx(&m)).is_pass());
    }

    #[test]
    fn test_timestamp_range_fails_when_before_min() {
        let mut m = test_manifest();
        let now = Utc::now();
        m.sealed_timestamp = now - Duration::hours(2);
        let cond = TimestampRangeCondition {
            min: now - Duration::hours(1),
            max: now + Duration::hours(1),
        };
        assert!(cond.evaluate(&ctx(&m)).is_fail());
    }

    #[test]
    fn test_timestamp_range_inclusive_bounds() {
        let mut m = test_manifest();
        let now = Utc::now();
        m.sealed_timestamp = now;
        let cond = TimestampRangeCondition {
            min: now,
            max: now,
        };
        assert!(cond.evaluate(&ctx(&m)).is_pass());
    }

    // -- TimestampFreshnessCondition --

    #[test]
    fn test_timestamp_freshness_passes_when_recent() {
        let mut m = test_manifest();
        let now = Utc::now();
        m.sealed_timestamp = now - Duration::seconds(30);
        let cond = TimestampFreshnessCondition {
            max_age_seconds: 60,
        };
        let c = PolicyContext::new(&m).with_now(now);
        assert!(cond.evaluate(&c).is_pass());
    }

    #[test]
    fn test_timestamp_freshness_fails_when_stale() {
        let mut m = test_manifest();
        let now = Utc::now();
        m.sealed_timestamp = now - Duration::hours(2);
        let cond = TimestampFreshnessCondition {
            max_age_seconds: 60,
        };
        let c = PolicyContext::new(&m).with_now(now);
        assert!(cond.evaluate(&c).is_fail());
    }

    // -- KeyIdCondition --

    #[test]
    fn test_key_id_passes_when_in_allowed_list() {
        let m = test_manifest();
        let cond = KeyIdCondition {
            allowed: vec!["pk_test".to_string(), "other".to_string()],
        };
        assert!(cond.evaluate(&ctx(&m)).is_pass());
    }

    #[test]
    fn test_key_id_fails_when_not_in_allowed_list() {
        let m = test_manifest();
        let cond = KeyIdCondition {
            allowed: vec!["other".to_string()],
        };
        assert!(cond.evaluate(&ctx(&m)).is_fail());
    }

    // -- TrustedKeyCondition --

    #[test]
    fn test_trusted_key_passes_when_trusted() {
        let m = test_manifest();
        let mut keys = BTreeMap::new();
        keys.insert("k1".to_string(), "pk_test".to_string());
        let c = PolicyContext::new(&m).with_trusted_keys(keys);
        let cond = TrustedKeyCondition {};
        assert!(cond.evaluate(&c).is_pass());
    }

    #[test]
    fn test_trusted_key_fails_when_not_trusted() {
        let m = test_manifest();
        let mut keys = BTreeMap::new();
        keys.insert("k1".to_string(), "different_key".to_string());
        let c = PolicyContext::new(&m).with_trusted_keys(keys);
        let cond = TrustedKeyCondition {};
        assert!(cond.evaluate(&c).is_fail());
    }

    #[test]
    fn test_trusted_key_fails_when_revoked() {
        let m = test_manifest();
        let mut keys = BTreeMap::new();
        keys.insert("k1".to_string(), "pk_test".to_string());
        let c = PolicyContext::new(&m)
            .with_trusted_keys(keys)
            .with_revoked_keys(vec!["pk_test".to_string()]);
        let cond = TrustedKeyCondition {};
        assert!(cond.evaluate(&c).is_fail());
    }

    #[test]
    fn test_trusted_key_skips_when_no_keys_configured() {
        let m = test_manifest();
        let c = PolicyContext::new(&m);
        let cond = TrustedKeyCondition {};
        assert!(cond.evaluate(&c).is_skip());
    }

    // -- ChainDepthCondition --

    #[test]
    fn test_chain_depth_passes_no_parent_min_one() {
        let m = test_manifest();
        let cond = ChainDepthCondition { min: 1 };
        assert!(cond.evaluate(&ctx(&m)).is_pass());
    }

    #[test]
    fn test_chain_depth_fails_no_parent_min_two() {
        let m = test_manifest();
        let cond = ChainDepthCondition { min: 2 };
        assert!(cond.evaluate(&ctx(&m)).is_fail());
    }

    #[test]
    fn test_chain_depth_from_metadata() {
        let mut m = test_manifest();
        m.metadata
            .insert("chain_depth".to_string(), serde_json::json!(5u64));
        let cond = ChainDepthCondition { min: 5 };
        assert!(cond.evaluate(&ctx(&m)).is_pass());
        let cond = ChainDepthCondition { min: 6 };
        assert!(cond.evaluate(&ctx(&m)).is_fail());
    }

    // -- BundleHashCondition --

    #[test]
    fn test_bundle_hash_passes_when_equal() {
        let m = test_manifest();
        let cond = BundleHashCondition {
            expected: "abc123".to_string(),
        };
        assert!(cond.evaluate(&ctx(&m)).is_pass());
    }

    #[test]
    fn test_bundle_hash_fails_when_mismatched() {
        let m = test_manifest();
        let cond = BundleHashCondition {
            expected: "wrong".to_string(),
        };
        assert!(cond.evaluate(&ctx(&m)).is_fail());
    }

    // -- NonceFreshCondition --

    #[test]
    fn test_nonce_fresh_passes_when_above_min() {
        let mut m = test_manifest();
        m.metadata
            .insert("nonce".to_string(), serde_json::json!(100u64));
        let cond = NonceFreshCondition { min_nonce: 50 };
        assert!(cond.evaluate(&ctx(&m)).is_pass());
    }

    #[test]
    fn test_nonce_fresh_fails_when_below_min() {
        let mut m = test_manifest();
        m.metadata
            .insert("nonce".to_string(), serde_json::json!(10u64));
        let cond = NonceFreshCondition { min_nonce: 50 };
        assert!(cond.evaluate(&ctx(&m)).is_fail());
    }

    #[test]
    fn test_nonce_fresh_fails_when_missing() {
        let m = test_manifest();
        let cond = NonceFreshCondition { min_nonce: 1 };
        assert!(cond.evaluate(&ctx(&m)).is_fail());
    }

    // -- SchemaVersionCondition --

    #[test]
    fn test_schema_version_passes_when_matching() {
        let m = test_manifest();
        let cond = SchemaVersionCondition {
            expected: crate::SCHEMA_VERSION.to_string(),
        };
        assert!(cond.evaluate(&ctx(&m)).is_pass());
    }

    #[test]
    fn test_schema_version_fails_when_mismatched() {
        let m = test_manifest();
        let cond = SchemaVersionCondition {
            expected: "99.99.99".to_string(),
        };
        assert!(cond.evaluate(&ctx(&m)).is_fail());
    }

    // -- MetadataFieldCondition --

    #[test]
    fn test_metadata_field_passes_when_key_exists() {
        let mut m = test_manifest();
        m.metadata
            .insert("env".to_string(), serde_json::json!("production"));
        let cond = MetadataFieldCondition {
            key: "env".to_string(),
            expected_value: None,
        };
        assert!(cond.evaluate(&ctx(&m)).is_pass());
    }

    #[test]
    fn test_metadata_field_passes_when_value_matches() {
        let mut m = test_manifest();
        m.metadata
            .insert("env".to_string(), serde_json::json!("production"));
        let cond = MetadataFieldCondition {
            key: "env".to_string(),
            expected_value: Some(serde_json::json!("production")),
        };
        assert!(cond.evaluate(&ctx(&m)).is_pass());
    }

    #[test]
    fn test_metadata_field_fails_when_value_differs() {
        let mut m = test_manifest();
        m.metadata
            .insert("env".to_string(), serde_json::json!("staging"));
        let cond = MetadataFieldCondition {
            key: "env".to_string(),
            expected_value: Some(serde_json::json!("production")),
        };
        assert!(cond.evaluate(&ctx(&m)).is_fail());
    }

    #[test]
    fn test_metadata_field_fails_when_key_missing() {
        let m = test_manifest();
        let cond = MetadataFieldCondition {
            key: "nonexistent".to_string(),
            expected_value: None,
        };
        assert!(cond.evaluate(&ctx(&m)).is_fail());
    }
}