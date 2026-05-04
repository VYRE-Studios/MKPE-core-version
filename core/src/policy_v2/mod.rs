//! # Policy Engine v2
//!
//! A trait-based, extensible policy evaluation system for MKPE provenance.
//!
//! ## Architecture
//!
//! - [`PolicyCondition`] — trait for pluggable evaluation logic
//! - [`PolicyContext`] — enriched input carrying a manifest and optional extras
//! - [`Policy`] — named, prioritized group of conditions with a combining mode
//! - [`PolicyOutcome`] — structured result: pass/fail per-condition, with reasons
//! - [`PolicyEngine`] — evaluates an ordered list of policies against a context
//! - [`ConditionRegistry`] — name-to-constructor map for JSON deserialization
//!
//! ## Migration from v1
//!
//! v1 used `PolicyCondition` as an enum and returned `Result<bool>`.
//! v2 wraps the same semantics in trait objects and returns `PolicyOutcome`
//! with per-condition detail. The v1 types remain available; v2 lives in
//! this module and reuses the same Manifest.

use crate::manifest::Manifest;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub mod conditions;
pub mod registry;

// Re-export the condition trait for convenience
pub use conditions::PolicyCondition;
// ---------------------------------------------------------------------------
// Error model
// ---------------------------------------------------------------------------

/// Errors specific to policy evaluation.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// A required field in the manifest/context was missing.
    #[error("missing required field: {0}")]
    MissingField(String),

    /// A condition could not be evaluated because its parameters were invalid.
    #[error("invalid condition parameters: {0}")]
    InvalidParameters(String),

    /// A policy reference could not be resolved (unknown condition name).
    #[error("unknown condition type: {0}")]
    UnknownConditionType(String),

    /// A policy file failed to parse.
    #[error("policy file parse error: {0}")]
    ParseError(String),

    /// An IO error reading a policy file.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// A JSON error deserializing policy data.
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// PolicyContext — what a condition evaluates against
// ---------------------------------------------------------------------------

/// Enriched evaluation context passed to every condition.
///
/// Carries the manifest being verified plus optional extra data
/// that conditions might need (e.g., trusted key sets, revocation lists,
/// pre-fetched timestamps).
#[derive(Debug, Clone)]
pub struct PolicyContext<'a> {
    /// The manifest under evaluation.
    pub manifest: &'a Manifest,

    /// Trusted public keys (key_id → base64 public key).
    pub trusted_keys: BTreeMap<String, String>,

    /// Revoked key IDs.
    pub revoked_keys: Vec<String>,

    /// Override "now" for deterministic testing. Uses `Utc::now()` if `None`.
    pub now_override: Option<DateTime<Utc>>,
}

impl<'a> PolicyContext<'a> {
    /// Create a minimal context from a manifest reference.
    pub fn new(manifest: &'a Manifest) -> Self {
        Self {
            manifest,
            trusted_keys: BTreeMap::new(),
            revoked_keys: Vec::new(),
            now_override: None,
        }
    }

    /// Set the trusted key map.
    pub fn with_trusted_keys(mut self, keys: BTreeMap<String, String>) -> Self {
        self.trusted_keys = keys;
        self
    }

    /// Set the revocation list.
    pub fn with_revoked_keys(mut self, keys: Vec<String>) -> Self {
        self.revoked_keys = keys;
        self
    }

    /// Override the current time for deterministic tests.
    pub fn with_now(mut self, now: DateTime<Utc>) -> Self {
        self.now_override = Some(now);
        self
    }

    /// Returns the effective "now" timestamp.
    pub fn now(&self) -> DateTime<Utc> {
        self.now_override.unwrap_or_else(Utc::now)
    }
}

// ---------------------------------------------------------------------------
// Condition result — single condition evaluation outcome
// ---------------------------------------------------------------------------

/// Outcome of a single condition check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConditionResult {
    /// The condition passed.
    Pass,
    /// The condition failed. `reason` is human-readable; `code` is a machine key.
    Fail {
        reason: String,
        code: String,
    },
    /// The condition could not be evaluated (e.g., missing data).
    Skip {
        reason: String,
    },
}

impl ConditionResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, ConditionResult::Pass)
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, ConditionResult::Fail { .. })
    }

    pub fn is_skip(&self) -> bool {
        matches!(self, ConditionResult::Skip { .. })
    }

    /// Convenience: fail with a reason and default code derived from it.
    pub fn fail(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        let code = reason
            .to_lowercase()
            .replace(' ', "_")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .collect::<String>();
        ConditionResult::Fail { reason, code }
    }

    pub fn skip(reason: impl Into<String>) -> Self {
        ConditionResult::Skip {
            reason: reason.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyOutcome — structured evaluation result for one policy
// ---------------------------------------------------------------------------

/// Severity level for a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    /// Informational — pass or fail has no enforcement effect.
    Info,
    /// Warning — failure should be flagged but not block.
    Warning,
    /// Critical — failure blocks the operation.
    Critical,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Warning
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// How conditions within a policy are combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CombineMode {
    /// All conditions must pass (AND).
    All,
    /// At least one condition must pass (OR).
    Any,
}

impl Default for CombineMode {
    fn default() -> Self {
        CombineMode::All
    }
}

/// The outcome of evaluating a single [`Policy`] against a context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOutcome {
    /// Name of the policy that was evaluated.
    pub policy_name: String,

    /// Overall pass/fail/skip for this policy.
    pub passed: bool,

    /// Per-condition results keyed by condition name.
    pub condition_results: Vec<(String, ConditionResult)>,

    /// Severity of this policy.
    pub severity: Severity,

    /// Combine mode used.
    pub combine_mode: CombineMode,

    /// Human-readable summary of why the policy passed or failed.
    pub summary: String,
}

impl PolicyOutcome {
    /// Build an outcome from per-condition results and a combining mode.
    pub fn from_results(
        policy_name: String,
        condition_results: Vec<(String, ConditionResult)>,
        combine_mode: CombineMode,
        severity: Severity,
    ) -> Self {
        let (passed, summary) = if condition_results.is_empty() {
            (true, "No conditions — vacuously true".to_string())
        } else {
            let pass_count = condition_results
                .iter()
                .filter(|(_, r)| r.is_pass())
                .count();
            let fail_count = condition_results
                .iter()
                .filter(|(_, r)| r.is_fail())
                .count();
            let skip_count = condition_results
                .iter()
                .filter(|(_, r)| r.is_skip())
                .count();

            let overall = match combine_mode {
                CombineMode::All => fail_count == 0 && skip_count == 0,
                CombineMode::Any => pass_count > 0,
            };

            let summary = if overall {
                format!(
                    "Passed ({}/{} conditions satisfied)",
                    pass_count,
                    condition_results.len()
                )
            } else {
                let failed: Vec<&str> = condition_results
                    .iter()
                    .filter(|(_, r)| r.is_fail())
                    .map(|(name, _)| name.as_str())
                    .collect();
                format!(
                    "Failed: conditions [{}] did not satisfy",
                    failed.join(", ")
                )
            };

            (overall, summary)
        };

        Self {
            policy_name,
            passed,
            condition_results,
            severity,
            combine_mode,
            summary,
        }
    }

    /// Convenience: did this policy pass?
    pub fn is_pass(&self) -> bool {
        self.passed
    }
}

// ---------------------------------------------------------------------------
// EngineOutcome — aggregate result across all policies
// ---------------------------------------------------------------------------

/// Aggregate result of evaluating all policies in an engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineOutcome {
    /// Per-policy outcomes, in evaluation order.
    pub policy_outcomes: Vec<PolicyOutcome>,

    /// Whether ALL critical policies passed.
    pub all_critical_passed: bool,

    /// Whether ALL policies (of any severity) passed.
    pub all_passed: bool,
}

impl EngineOutcome {
    fn from_policy_outcomes(outcomes: Vec<PolicyOutcome>) -> Self {
        let all_critical_passed = outcomes
            .iter()
            .filter(|o| o.severity == Severity::Critical)
            .all(|o| o.passed);
        let all_passed = outcomes.iter().all(|o| o.passed);

        Self {
            policy_outcomes: outcomes,
            all_critical_passed,
            all_passed,
        }
    }

    /// Which policies failed, with their severity?
    pub fn failed_policies(&self) -> Vec<(&str, Severity)> {
        self.policy_outcomes
            .iter()
            .filter(|o| !o.passed)
            .map(|o| (o.policy_name.as_str(), o.severity))
            .collect()
    }

    /// Human-readable report.
    pub fn report(&self) -> String {
        let mut lines = Vec::new();
        lines.push("=== Policy Evaluation Report ===".to_string());
        for outcome in &self.policy_outcomes {
            let status = if outcome.passed { "PASS" } else { "FAIL" };
            lines.push(format!(
                "[{}] {} (severity: {}): {}",
                status, outcome.policy_name, outcome.severity, outcome.summary
            ));
            for (name, result) in &outcome.condition_results {
                let marker = match result {
                    ConditionResult::Pass => "✓",
                    ConditionResult::Fail { .. } => "✗",
                    ConditionResult::Skip { .. } => "⊘",
                };
                lines.push(format!("  {} {}: {:?}", marker, name, result));
            }
        }
        lines.push(format!(
            "Critical policies: {}",
            if self.all_critical_passed {
                "ALL PASSED"
            } else {
                "SOME FAILED"
            }
        ));
        lines.push(format!(
            "Overall: {}",
            if self.all_passed {
                "ALL PASSED"
            } else {
                "SOME FAILED"
            }
        ));
        lines.join("\n")
    }
}
// ---------------------------------------------------------------------------
// Policy — named group of conditions with combine mode and severity
// ---------------------------------------------------------------------------

/// A named, ordered collection of conditions with a combining mode and severity.
///
/// This is the v2 equivalent of the v1 `Policy` struct, but uses trait
/// objects instead of enum variants, and carries severity information.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Human-readable name (e.g., "production_integrity").
    pub name: String,

    /// Conditions to evaluate, in order.
    pub conditions: Vec<Box<dyn PolicyCondition>>,

    /// How to combine condition results.
    pub combine_mode: CombineMode,

    /// Severity when this policy fails.
    pub severity: Severity,
}

impl Policy {
    /// Create a new policy with AND combine mode and Warning severity.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            conditions: Vec::new(),
            combine_mode: CombineMode::All,
            severity: Severity::Warning,
        }
    }

    /// Set the combine mode.
    pub fn with_combine_mode(mut self, mode: CombineMode) -> Self {
        self.combine_mode = mode;
        self
    }

    /// Set the severity.
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Add a condition.
    pub fn with_condition(mut self, condition: Box<dyn PolicyCondition>) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Evaluate this policy against a context.
    pub fn evaluate(&self, ctx: &PolicyContext<'_>) -> PolicyOutcome {
        let condition_results: Vec<(String, ConditionResult)> = self
            .conditions
            .iter()
            .map(|c| (c.name().to_string(), c.evaluate(ctx)))
            .collect();

        PolicyOutcome::from_results(
            self.name.clone(),
            condition_results,
            self.combine_mode,
            self.severity,
        )
    }
}

// ---------------------------------------------------------------------------
// PolicyEngine — evaluates ordered policies and aggregates results
// ---------------------------------------------------------------------------

/// The v2 policy engine.
///
/// Holds an ordered list of policies and evaluates them all against a context,
/// producing an [`EngineOutcome`] with per-policy, per-condition detail.
///
/// Unlike v1 which returned `Result<bool>`, the v2 engine always succeeds
/// with a full report — the caller inspects `EngineOutcome` to decide
/// what to enforce.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    /// Ordered list of policies to evaluate.
    pub policies: Vec<Policy>,
}

impl PolicyEngine {
    /// Create an empty engine.
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Add a policy.
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policies.push(policy);
        self
    }

    /// Evaluate all policies against the given context.
    ///
    /// Returns an `EngineOutcome` with per-policy detail. This never
    /// returns an error — individual condition failures are captured in
    /// the outcome, not bubbled up as `Err`.
    pub fn evaluate(&self, ctx: &PolicyContext<'_>) -> EngineOutcome {
        let outcomes: Vec<PolicyOutcome> =
            self.policies.iter().map(|p| p.evaluate(ctx)).collect();
        EngineOutcome::from_policy_outcomes(outcomes)
    }

    /// Convenience: returns `true` only if all critical policies pass.
    pub fn critical_pass(&self, ctx: &PolicyContext<'_>) -> bool {
        self.evaluate(ctx).all_critical_passed
    }

    /// Convenience: returns `true` only if ALL policies (any severity) pass.
    pub fn all_pass(&self, ctx: &PolicyContext<'_>) -> bool {
        self.evaluate(ctx).all_passed
    }

    /// Load policies from a JSON policy file using a condition registry.
    ///
    /// The registry maps condition type names to deserializers.
    pub fn load_from_file(
        path: &std::path::Path,
        registry: &registry::ConditionRegistry,
    ) -> Result<Self, PolicyError> {
        let contents = std::fs::read_to_string(path)?;
        let policy_file: registry::PolicyFile = serde_json::from_str(&contents)?;
        Self::from_policy_file(&policy_file, registry)
    }

    /// Build an engine from a [`PolicyFile`] definition using a registry.
    pub fn from_policy_file(
        file: &registry::PolicyFile,
        registry: &registry::ConditionRegistry,
    ) -> Result<Self, PolicyError> {
        let mut engine = Self::new();

        for def in &file.policies {
            let combine_mode = match def.combine.as_str() {
                "any" => CombineMode::Any,
                _ => CombineMode::All,
            };

            let severity = match def.severity.as_str() {
                "critical" => Severity::Critical,
                "info" => Severity::Info,
                _ => Severity::Warning,
            };

            let mut policy = Policy::new(&def.name)
                .with_combine_mode(combine_mode)
                .with_severity(severity);

            for cond_desc in &def.conditions {
                let condition = registry.deserialize(&cond_desc.type_name, &cond_desc.params)?;
                policy = policy.with_condition(condition);
            }

            engine = engine.with_policy(policy);
        }

        Ok(engine)
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}