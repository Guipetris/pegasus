use std::path::{Path, PathBuf};

use chrono::Utc;
use walkdir::WalkDir;

use pegasus_types::error::PegasusError;
use pegasus_types::types::{EvidenceEnvelope, PolicyDecision, PolicyEvaluationResult, PolicyId};

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

struct LoadedPolicy {
    id: PolicyId,
    path: PathBuf,
    source: String,
    /// The fully-qualified data path derived from the Rego package declaration,
    /// e.g. `"data.compliance.tls.certificate_chain_valid"`.
    data_path: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Engine that loads Rego policies from disk and evaluates them against an
/// [`EvidenceEnvelope`].
pub struct PolicyEngine {
    policies: Vec<LoadedPolicy>,
}

impl PolicyEngine {
    /// Load all `*.rego` files under `dir`, skipping `*_test.rego` files.
    ///
    /// Each file is parsed to extract its `package` declaration, which is
    /// used to derive the `data.*` query path and the policy ID.
    pub fn from_directory(dir: impl AsRef<Path>) -> Result<Self, PegasusError> {
        let dir = dir.as_ref();
        let mut policies = Vec::new();

        for entry in WalkDir::new(dir).follow_links(true).into_iter() {
            let entry = entry.map_err(|e| PegasusError::IoError {
                path: dir.to_path_buf(),
                source: e.into(),
            })?;

            let path = entry.path();

            // Only process .rego files
            if !path.extension().map(|e| e == "rego").unwrap_or(false) {
                continue;
            }

            // Skip OPA test files
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with("_test.rego"))
                .unwrap_or(false)
            {
                continue;
            }

            let source = std::fs::read_to_string(path).map_err(|e| PegasusError::IoError {
                path: path.to_path_buf(),
                source: e,
            })?;

            let data_path =
                extract_package_path(&source).ok_or_else(|| PegasusError::PolicyLoadError {
                    path: path.to_path_buf(),
                    reason: "could not find package declaration".to_string(),
                })?;

            // Derive a stable ID from the path relative to the policies directory
            let rel = path.strip_prefix(dir).unwrap_or(path);
            let id = PolicyId(
                rel.to_string_lossy()
                    .trim_end_matches(".rego")
                    .replace(std::path::MAIN_SEPARATOR, "/")
                    .to_string(),
            );

            policies.push(LoadedPolicy {
                id,
                path: path.to_path_buf(),
                source,
                data_path,
            });
        }

        Ok(Self { policies })
    }

    /// Evaluate all loaded policies against the given envelope.
    ///
    /// The Rego input is the envelope's `raw_payload` (the actual evidence data),
    /// enriched with `evaluation_time` and `collected_at` from the envelope metadata.
    /// This means policies access fields directly (e.g., `input.certificates`)
    /// rather than through a wrapper (e.g., `input.envelope.raw_payload.certificates`).
    ///
    /// A per-policy evaluation failure (e.g. an unsatisfiable rule) is
    /// captured as [`PolicyDecision::Error`] rather than aborting the batch.
    pub fn evaluate(
        &self,
        envelope: &EvidenceEnvelope,
    ) -> Result<Vec<PolicyEvaluationResult>, PegasusError> {
        // Build the Rego input from the raw_payload, enriched with envelope metadata.
        // Policies expect `input.certificates`, `input.evaluation_time`, etc. directly.
        let mut input_value = envelope.raw_payload.clone();
        if let Some(obj) = input_value.as_object_mut() {
            // Inject evaluation_time (current time) for expiry policies
            obj.entry("evaluation_time").or_insert_with(|| {
                serde_json::Value::String(
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                )
            });
            // Inject collected_at from envelope metadata for timestamp policies
            obj.entry("collected_at").or_insert_with(|| {
                serde_json::Value::String(
                    envelope
                        .collected_at
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                )
            });
        }
        let input_json = serde_json::to_string(&input_value)?;

        let mut results = Vec::with_capacity(self.policies.len());

        for policy in &self.policies {
            let result = evaluate_single_policy(policy, &input_json, envelope);
            results.push(result);
        }

        Ok(results)
    }

    /// Returns the number of loaded policies.
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Returns a slice of all loaded policy IDs.
    pub fn policy_ids(&self) -> Vec<&PolicyId> {
        self.policies.iter().map(|p| &p.id).collect()
    }
}

// ---------------------------------------------------------------------------
// Per-policy evaluation (never panics; maps errors to PolicyDecision::Error)
// ---------------------------------------------------------------------------

fn evaluate_single_policy(
    policy: &LoadedPolicy,
    input_json: &str,
    envelope: &EvidenceEnvelope,
) -> PolicyEvaluationResult {
    let outcome = try_evaluate_policy(policy, input_json);

    let (decision, reason) = match outcome {
        Ok((d, r)) => (d, r),
        Err(e) => (PolicyDecision::Error, format!("evaluation error: {}", e)),
    };

    PolicyEvaluationResult {
        policy_id: policy.id.clone(),
        decision,
        reason,
        evaluated_at: Utc::now(),
        evidence_hash: envelope.hash().clone(),
        metadata: None,
    }
}

/// Inner fallible evaluation — returns `(decision, reason)` on success.
fn try_evaluate_policy(
    policy: &LoadedPolicy,
    input_json: &str,
) -> Result<(PolicyDecision, String), String> {
    // Fresh engine per policy evaluation for full isolation.
    let mut engine = regorus::Engine::new();

    // Load the policy source.
    engine
        .add_policy(
            policy.path.to_string_lossy().to_string(),
            policy.source.clone(),
        )
        .map_err(|e| format!("failed to add policy: {}", e))?;

    // Set input document.
    let input_value = regorus::Value::from_json_str(input_json)
        .map_err(|e| format!("failed to parse input JSON: {}", e))?;
    engine.set_input(input_value);

    // Query `data.<pkg>.decision`
    let decision_path = format!("{}.decision", policy.data_path);
    let decision_value = engine
        .eval_rule(decision_path)
        .map_err(|e| format!("failed to eval decision rule: {}", e))?;

    let decision_str = match &decision_value {
        regorus::Value::String(s) => s.as_ref().to_string(),
        regorus::Value::Undefined => "skip".to_string(),
        other => {
            return Err(format!("unexpected decision value type: {:?}", other));
        }
    };

    let decision = parse_policy_decision(&decision_str).unwrap_or(PolicyDecision::Error);

    // Query `data.<pkg>.reason`
    let reason_path = format!("{}.reason", policy.data_path);
    let reason_value = engine
        .eval_rule(reason_path)
        .map_err(|e| format!("failed to eval reason rule: {}", e))?;

    let reason = match &reason_value {
        regorus::Value::String(s) => s.as_ref().to_string(),
        regorus::Value::Undefined => format!("no reason provided (decision: {})", decision_str),
        other => format!("unexpected reason value type: {:?}", other),
    };

    Ok((decision, reason))
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Parse the `package` declaration from Rego source and return the
/// fully-qualified `data.*` path.
///
/// `package compliance.tls.certificate_chain_valid`
/// → `"data.compliance.tls.certificate_chain_valid"`
pub fn extract_package_path(source: &str) -> Option<String> {
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("package") {
            let pkg = rest.trim();
            if !pkg.is_empty()
                && pkg
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '.' || c == '_')
            {
                return Some(format!("data.{}", pkg));
            }
        }
    }
    None
}

/// Map a Rego decision string to [`PolicyDecision`].
pub fn parse_policy_decision(s: &str) -> Option<PolicyDecision> {
    match s {
        "pass" => Some(PolicyDecision::Pass),
        "fail" => Some(PolicyDecision::Fail),
        "warn" => Some(PolicyDecision::Warn),
        "error" => Some(PolicyDecision::Error),
        "skip" => Some(PolicyDecision::Skip),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_package_path() {
        let src = "package compliance.tls.certificate_chain_valid\n\nimport rego.v1\n";
        assert_eq!(
            extract_package_path(src),
            Some("data.compliance.tls.certificate_chain_valid".to_string())
        );
    }

    #[test]
    fn test_extract_package_path_none() {
        let src = "# no package line here\nimport rego.v1\n";
        assert_eq!(extract_package_path(src), None);
    }

    #[test]
    fn test_parse_policy_decision() {
        assert_eq!(parse_policy_decision("pass"), Some(PolicyDecision::Pass));
        assert_eq!(parse_policy_decision("fail"), Some(PolicyDecision::Fail));
        assert_eq!(parse_policy_decision("warn"), Some(PolicyDecision::Warn));
        assert_eq!(parse_policy_decision("error"), Some(PolicyDecision::Error));
        assert_eq!(parse_policy_decision("skip"), Some(PolicyDecision::Skip));
        assert_eq!(parse_policy_decision("unknown"), None);
    }
}
