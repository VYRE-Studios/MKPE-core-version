//! Integration and engine-level tests for policy_v2.
//!
//! Tests the full pipeline: Policy → PolicyEngine → EngineOutcome,
//! policy file loading, JSON round-trips, and edge cases.

use morse_kirby_core::manifest::Manifest;
use morse_kirby_core::policy_v2::conditions::*;
use morse_kirby_core::policy_v2::registry::*;
use morse_kirby_core::policy_v2::*;

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

// ---------------------------------------------------------------------------
// Policy composition
// ---------------------------------------------------------------------------

#[test]
fn test_policy_require_all_passes_when_all_conditions_match() {
    let m = test_manifest();
    let policy = Policy::new("integrity")
        .with_severity(Severity::Critical)
        .with_condition(Box::new(BundleHashCondition {
            expected: "abc123".to_string(),
        }))
        .with_condition(Box::new(KeyIdCondition {
            allowed: vec!["pk_test".to_string()],
        }));

    let outcome = policy.evaluate(&ctx(&m));
    assert!(outcome.passed);
    assert_eq!(outcome.severity, Severity::Critical);
    assert_eq!(outcome.combine_mode, CombineMode::All);
}

#[test]
fn test_policy_require_all_fails_when_one_condition_fails() {
    let m = test_manifest();
    let policy = Policy::new("integrity")
        .with_condition(Box::new(BundleHashCondition {
            expected: "abc123".to_string(),
        }))
        .with_condition(Box::new(KeyIdCondition {
            allowed: vec!["wrong_key".to_string()],
        }));

    let outcome = policy.evaluate(&ctx(&m));
    assert!(!outcome.passed);
}

#[test]
fn test_policy_require_any_passes_when_one_matches() {
    let m = test_manifest();
    let policy = Policy::new("flexible")
        .with_combine_mode(CombineMode::Any)
        .with_condition(Box::new(BundleHashCondition {
            expected: "wrong_hash".to_string(),
        }))
        .with_condition(Box::new(KeyIdCondition {
            allowed: vec!["pk_test".to_string()],
        }));

    let outcome = policy.evaluate(&ctx(&m));
    assert!(outcome.passed);
}

#[test]
fn test_policy_require_any_fails_when_none_match() {
    let m = test_manifest();
    let policy = Policy::new("flexible")
        .with_combine_mode(CombineMode::Any)
        .with_condition(Box::new(BundleHashCondition {
            expected: "wrong_hash".to_string(),
        }))
        .with_condition(Box::new(KeyIdCondition {
            allowed: vec!["wrong_key".to_string()],
        }));

    let outcome = policy.evaluate(&ctx(&m));
    assert!(!outcome.passed);
}

#[test]
fn test_policy_empty_conditions_vacuously_true() {
    let m = test_manifest();
    let policy = Policy::new("empty");
    let outcome = policy.evaluate(&ctx(&m));
    assert!(outcome.passed);
}

#[test]
fn test_policy_skip_counts_as_fail_in_all_mode() {
    let m = test_manifest();
    let policy = Policy::new("with_skip")
        .with_condition(Box::new(TrustedKeyCondition {})); // No trusted keys → Skip

    let outcome = policy.evaluate(&ctx(&m));
    // In All mode, a Skip is treated as not-pass
    assert!(!outcome.passed);
}

#[test]
fn test_policy_skip_does_not_satisfy_any_mode() {
    let m = test_manifest();
    let policy = Policy::new("skip_any")
        .with_combine_mode(CombineMode::Any)
        .with_condition(Box::new(TrustedKeyCondition {})); // Skip, not Pass

    let outcome = policy.evaluate(&ctx(&m));
    assert!(!outcome.passed); // Skip != Pass
}

// ---------------------------------------------------------------------------
// PolicyEngine evaluation
// ---------------------------------------------------------------------------

#[test]
fn test_engine_all_policies_pass() {
    let m = test_manifest();
    let engine = PolicyEngine::new()
        .with_policy(
            Policy::new("hash_check")
                .with_severity(Severity::Critical)
                .with_condition(Box::new(BundleHashCondition {
                    expected: "abc123".to_string(),
                })),
        )
        .with_policy(
            Policy::new("key_check")
                .with_condition(Box::new(KeyIdCondition {
                    allowed: vec!["pk_test".to_string()],
                })),
        );

    let outcome = engine.evaluate(&ctx(&m));
    assert!(outcome.all_passed);
    assert!(outcome.all_critical_passed);
}

#[test]
fn test_engine_critical_failure_blocks() {
    let m = test_manifest();
    let engine = PolicyEngine::new()
        .with_policy(
            Policy::new("hash_check")
                .with_severity(Severity::Critical)
                .with_condition(Box::new(BundleHashCondition {
                    expected: "wrong".to_string(),
                })),
        );

    let outcome = engine.evaluate(&ctx(&m));
    assert!(!outcome.all_passed);
    assert!(!outcome.all_critical_passed);
}

#[test]
fn test_engine_warning_failure_does_not_block_critical() {
    let m = test_manifest();
    let engine = PolicyEngine::new()
        .with_policy(
            Policy::new("optional_check")
                .with_severity(Severity::Warning)
                .with_condition(Box::new(BundleHashCondition {
                    expected: "wrong".to_string(),
                })),
        );

    let outcome = engine.evaluate(&ctx(&m));
    assert!(!outcome.all_passed); // overall includes warning
    assert!(outcome.all_critical_passed); // no critical policies failed
}

#[test]
fn test_engine_empty_is_vacuously_true() {
    let m = test_manifest();
    let engine = PolicyEngine::new();
    let outcome = engine.evaluate(&ctx(&m));
    assert!(outcome.all_passed);
    assert!(outcome.all_critical_passed);
}

#[test]
fn test_engine_critical_pass_convenience_method() {
    let m = test_manifest();
    let engine = PolicyEngine::new()
        .with_policy(
            Policy::new("hash_check")
                .with_severity(Severity::Critical)
                .with_condition(Box::new(BundleHashCondition {
                    expected: "abc123".to_string(),
                })),
        );

    assert!(engine.critical_pass(&ctx(&m)));
}

#[test]
fn test_engine_all_pass_convenience_method() {
    let m = test_manifest();
    let engine = PolicyEngine::new()
        .with_policy(
            Policy::new("check")
                .with_condition(Box::new(KeyIdCondition {
                    allowed: vec!["pk_test".to_string()],
                })),
        );

    assert!(engine.all_pass(&ctx(&m)));
}

// ---------------------------------------------------------------------------
// EngineOutcome reporting
// ---------------------------------------------------------------------------

#[test]
fn test_engine_outcome_report_contains_failed_policies() {
    let m = test_manifest();
    let engine = PolicyEngine::new()
        .with_policy(
            Policy::new("fail_policy")
                .with_severity(Severity::Critical)
                .with_condition(Box::new(BundleHashCondition {
                    expected: "wrong".to_string(),
                })),
        )
        .with_policy(
            Policy::new("pass_policy")
                .with_condition(Box::new(BundleHashCondition {
                    expected: "abc123".to_string(),
                })),
        );

    let outcome = engine.evaluate(&ctx(&m));
    let failed = outcome.failed_policies();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].0, "fail_policy");
    assert_eq!(failed[0].1, Severity::Critical);
}

#[test]
fn test_engine_outcome_report_is_readable() {
    let m = test_manifest();
    let engine = PolicyEngine::new()
        .with_policy(
            Policy::new("integrity")
                .with_severity(Severity::Critical)
                .with_condition(Box::new(BundleHashCondition {
                    expected: "abc123".to_string(),
                }))
                .with_condition(Box::new(KeyIdCondition {
                    allowed: vec!["pk_test".to_string()],
                })),
        );

    let outcome = engine.evaluate(&ctx(&m));
    let report = outcome.report();
    assert!(report.contains("PASS"));
    assert!(report.contains("integrity"));
    assert!(report.contains("bundle_hash"));
    assert!(report.contains("key_id"));
    assert!(report.contains("ALL PASSED"));
}

// ---------------------------------------------------------------------------
// Policy file loading via registry
// ---------------------------------------------------------------------------

#[test]
fn test_policy_file_load_and_evaluate() {
    let m = test_manifest();
    let policy_file = PolicyFile {
        policies: vec![PolicyDefinition {
            name: "file_policy".to_string(),
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

    let registry = ConditionRegistry::with_builtins();
    let engine = PolicyEngine::from_policy_file(&policy_file, &registry).unwrap();
    let outcome = engine.evaluate(&ctx(&m));
    assert!(outcome.all_passed);
    assert!(outcome.all_critical_passed);
}

#[test]
fn test_policy_file_load_from_disk() {
    let policy_file = PolicyFile {
        policies: vec![PolicyDefinition {
            name: "disk_policy".to_string(),
            combine: "all".to_string(),
            severity: "warning".to_string(),
            conditions: vec![ConditionDescriptor {
                type_name: "key_version".to_string(),
                params: serde_json::json!({"min": 1}),
            }],
        }],
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.json");
    let json = serde_json::to_string_pretty(&policy_file).unwrap();
    std::fs::write(&path, &json).unwrap();

    let registry = ConditionRegistry::with_builtins();
    let engine = PolicyEngine::load_from_file(&path, &registry).unwrap();

    let m = test_manifest();
    let outcome = engine.evaluate(&ctx(&m));
    assert!(outcome.all_passed);
}

#[test]
fn test_policy_file_rejects_unknown_condition_type() {
    let policy_file = PolicyFile {
        policies: vec![PolicyDefinition {
            name: "bad_policy".to_string(),
            combine: "all".to_string(),
            severity: "warning".to_string(),
            conditions: vec![ConditionDescriptor {
                type_name: "nonexistent_condition".to_string(),
                params: serde_json::json!({}),
            }],
        }],
    };

    let registry = ConditionRegistry::with_builtins();
    let result = PolicyEngine::from_policy_file(&policy_file, &registry);
    assert!(result.is_err());
    match result.unwrap_err() {
        PolicyError::UnknownConditionType(name) => {
            assert_eq!(name, "nonexistent_condition");
        }
        other => panic!("Expected UnknownConditionType, got {:?}", other),
    }
}

#[test]
fn test_policy_file_with_any_combine_mode() {
    let policy_file = PolicyFile {
        policies: vec![PolicyDefinition {
            name: "any_policy".to_string(),
            combine: "any".to_string(),
            severity: "info".to_string(),
            conditions: vec![
                ConditionDescriptor {
                    type_name: "bundle_hash".to_string(),
                    params: serde_json::json!({"expected": "wrong"}),
                },
                ConditionDescriptor {
                    type_name: "key_id".to_string(),
                    params: serde_json::json!({"allowed": ["pk_test"]}),
                },
            ],
        }],
    };

    let registry = ConditionRegistry::with_builtins();
    let engine = PolicyEngine::from_policy_file(&policy_file, &registry).unwrap();

    let m = test_manifest();
    let outcome = engine.evaluate(&ctx(&m));
    assert!(outcome.all_passed); // Any mode → one passing condition suffices
}

#[test]
fn test_policy_file_with_info_severity() {
    let policy_file = PolicyFile {
        policies: vec![PolicyDefinition {
            name: "info_policy".to_string(),
            combine: "all".to_string(),
            severity: "info".to_string(),
            conditions: vec![ConditionDescriptor {
                type_name: "bundle_hash".to_string(),
                params: serde_json::json!({"expected": "wrong"}),
            }],
        }],
    };

    let registry = ConditionRegistry::with_builtins();
    let engine = PolicyEngine::from_policy_file(&policy_file, &registry).unwrap();

    let m = test_manifest();
    let outcome = engine.evaluate(&ctx(&m));
    assert!(!outcome.all_passed);
    assert!(outcome.all_critical_passed); // Info severity → not critical
}

#[test]
fn test_policy_file_invalid_params_produces_error() {
    let policy_file = PolicyFile {
        policies: vec![PolicyDefinition {
            name: "bad_params".to_string(),
            combine: "all".to_string(),
            severity: "warning".to_string(),
            conditions: vec![ConditionDescriptor {
                type_name: "key_version".to_string(),
                params: serde_json::json!({}), // missing "min"
            }],
        }],
    };

    let registry = ConditionRegistry::with_builtins();
    let result = PolicyEngine::from_policy_file(&policy_file, &registry);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Multiple policies with mixed severities
// ---------------------------------------------------------------------------

#[test]
fn test_mixed_severity_policies() {
    let m = test_manifest();
    let engine = PolicyEngine::new()
        .with_policy(
            Policy::new("critical_hash")
                .with_severity(Severity::Critical)
                .with_condition(Box::new(BundleHashCondition {
                    expected: "abc123".to_string(),
                })),
        )
        .with_policy(
            Policy::new("info_chain")
                .with_severity(Severity::Info)
                .with_condition(Box::new(ChainDepthCondition { min: 10 })), // will fail
        )
        .with_policy(
            Policy::new("warn_key")
                .with_severity(Severity::Warning)
                .with_condition(Box::new(KeyIdCondition {
                    allowed: vec!["pk_test".to_string()],
                })),
        );

    let outcome = engine.evaluate(&ctx(&m));
    assert!(outcome.all_critical_passed); // critical passed
    assert!(!outcome.all_passed); // info_chain failed

    let failed = outcome.failed_policies();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].0, "info_chain");
    assert_eq!(failed[0].1, Severity::Info);
}

// ---------------------------------------------------------------------------
// TimestampFreshness with context time override
// ---------------------------------------------------------------------------

#[test]
fn test_timestamp_freshness_with_context_override() {
    let mut m = test_manifest();
    let now = chrono::Utc::now();
    m.sealed_timestamp = now - chrono::Duration::seconds(30);

    let engine = PolicyEngine::new()
        .with_policy(
            Policy::new("freshness")
                .with_severity(Severity::Critical)
                .with_condition(Box::new(TimestampFreshnessCondition {
                    max_age_seconds: 60,
                })),
        );

    let ctx = PolicyContext::new(&m).with_now(now);
    let outcome = engine.evaluate(&ctx);
    assert!(outcome.all_critical_passed);
}

#[test]
fn test_timestamp_freshness_expired() {
    let mut m = test_manifest();
    let now = chrono::Utc::now();
    m.sealed_timestamp = now - chrono::Duration::hours(24);

    let engine = PolicyEngine::new()
        .with_policy(
            Policy::new("freshness")
                .with_severity(Severity::Critical)
                .with_condition(Box::new(TimestampFreshnessCondition {
                    max_age_seconds: 60,
                })),
        );

    let ctx = PolicyContext::new(&m).with_now(now);
    let outcome = engine.evaluate(&ctx);
    assert!(!outcome.all_critical_passed);
}

// ---------------------------------------------------------------------------
// TrustedKey condition with enriched context
// ---------------------------------------------------------------------------

#[test]
fn test_trusted_key_in_engine_pipeline() {
    let m = test_manifest();
    let mut keys = std::collections::BTreeMap::new();
    keys.insert("k1".to_string(), "pk_test".to_string());

    let engine = PolicyEngine::new()
        .with_policy(
            Policy::new("trust")
                .with_severity(Severity::Critical)
                .with_condition(Box::new(TrustedKeyCondition {})),
        );

    let ctx = PolicyContext::new(&m).with_trusted_keys(keys);
    let outcome = engine.evaluate(&ctx);
    assert!(outcome.all_critical_passed);
}

#[test]
fn test_trusted_key_revoked_in_pipeline() {
    let m = test_manifest();
    let mut keys = std::collections::BTreeMap::new();
    keys.insert("k1".to_string(), "pk_test".to_string());

    let engine = PolicyEngine::new()
        .with_policy(
            Policy::new("trust")
                .with_severity(Severity::Critical)
                .with_condition(Box::new(TrustedKeyCondition {})),
        );

    let ctx = PolicyContext::new(&m)
        .with_trusted_keys(keys)
        .with_revoked_keys(vec!["pk_test".to_string()]);
    let outcome = engine.evaluate(&ctx);
    assert!(!outcome.all_critical_passed);
}

// ---------------------------------------------------------------------------
// SchemaVersion and MetadataField in policy pipeline
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_in_engine() {
    let m = test_manifest();
    let engine = PolicyEngine::new()
        .with_policy(
            Policy::new("schema")
                .with_condition(Box::new(SchemaVersionCondition {
                    expected: morse_kirby_core::SCHEMA_VERSION.to_string(),
                })),
        );

    let outcome = engine.evaluate(&ctx(&m));
    assert!(outcome.all_passed);
}

#[test]
fn test_metadata_field_in_engine() {
    let mut m = test_manifest();
    m.metadata
        .insert("env".to_string(), serde_json::json!("production"));

    let engine = PolicyEngine::new()
        .with_policy(
            Policy::new("env_check")
                .with_severity(Severity::Critical)
                .with_condition(Box::new(MetadataFieldCondition {
                    key: "env".to_string(),
                    expected_value: Some(serde_json::json!("production")),
                })),
        );

    let outcome = engine.evaluate(&ctx(&m));
    assert!(outcome.all_critical_passed);
}

// ---------------------------------------------------------------------------
// JSON round-trip of policy file
// ---------------------------------------------------------------------------

#[test]
fn test_policy_file_json_round_trip() {
    let policy_file = PolicyFile {
        policies: vec![
            PolicyDefinition {
                name: "critical_integrity".to_string(),
                combine: "all".to_string(),
                severity: "critical".to_string(),
                conditions: vec![
                    ConditionDescriptor {
                        type_name: "bundle_hash".to_string(),
                        params: serde_json::json!({"expected": "deadbeef"}),
                    },
                    ConditionDescriptor {
                        type_name: "nonce_fresh".to_string(),
                        params: serde_json::json!({"min_nonce": 42}),
                    },
                ],
            },
            PolicyDefinition {
                name: "optional_check".to_string(),
                combine: "any".to_string(),
                severity: "info".to_string(),
                conditions: vec![ConditionDescriptor {
                    type_name: "key_id".to_string(),
                    params: serde_json::json!({"allowed": ["key1", "key2"]}),
                }],
            },
        ],
    };

    let json = serde_json::to_string_pretty(&policy_file).unwrap();
    let parsed: PolicyFile = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, policy_file);
}

// ---------------------------------------------------------------------------
// ConditionResult convenience methods
// ---------------------------------------------------------------------------

#[test]
fn test_condition_result_fail_convenience() {
    let result = ConditionResult::fail("Something went wrong");
    match result {
        ConditionResult::Fail { reason, code } => {
            assert_eq!(reason, "Something went wrong");
            assert_eq!(code, "something_went_wrong");
        }
        _ => panic!("Expected Fail"),
    }
}

#[test]
fn test_condition_result_skip_convenience() {
    let result = ConditionResult::skip("Not applicable");
    match result {
        ConditionResult::Skip { reason } => {
            assert_eq!(reason, "Not applicable");
        }
        _ => panic!("Expected Skip"),
    }
}