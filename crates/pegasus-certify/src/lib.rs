//! Certification engine: load TOML profiles, map policy results to controls, compute scores.

use pegasus_types::error::PegasusError;
use pegasus_types::types::PolicyEvaluationResult;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Profile types (parsed from TOML) ───────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CertificationProfile {
    pub certification: CertificationMeta,
    pub controls: Vec<Control>,
}

#[derive(Debug, Deserialize)]
pub struct CertificationMeta {
    pub id: String,
    pub name: String,
    pub authority: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default = "default_threshold")]
    pub pass_threshold: f64,
    #[serde(default = "default_true")]
    pub critical_must_pass: bool,
}

fn default_threshold() -> f64 {
    0.85
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct Control {
    pub id: String,
    pub title: String,
    pub description: String,
    pub policies: Vec<String>,
    pub required_decision: String,
    pub severity: String,
}

// ── Result types ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CertificationResult {
    pub standard_id: String,
    pub standard_name: String,
    pub score: f64,
    pub verdict: String, // "pass", "fail", "conditional"
    pub controls_passed: usize,
    pub controls_total: usize,
    pub control_results: Vec<ControlResult>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ControlResult {
    pub id: String,
    pub title: String,
    pub passed: bool,
    pub severity: String,
    pub policy_decisions: Vec<(String, String)>, // (policy_id, decision)
}

impl CertificationResult {
    pub fn from_controls(
        controls: Vec<ControlResult>,
        threshold: f64,
        critical_must_pass: bool,
    ) -> Self {
        let total = controls.len();
        let passed = controls.iter().filter(|c| c.passed).count();
        let score = if total == 0 {
            1.0
        } else {
            passed as f64 / total as f64
        };

        let critical_failed = critical_must_pass
            && controls
                .iter()
                .any(|c| !c.passed && c.severity == "critical");

        let verdict = if critical_failed {
            "fail".to_string()
        } else if score >= threshold {
            "pass".to_string()
        } else if score >= threshold * 0.8 {
            "conditional".to_string()
        } else {
            "fail".to_string()
        };

        Self {
            standard_id: String::new(),
            standard_name: String::new(),
            score,
            verdict,
            controls_passed: passed,
            controls_total: total,
            control_results: controls,
        }
    }
}

// ── Profile loading ────────────────────────────────────────────────────

impl CertificationProfile {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, PegasusError> {
        let path = path.as_ref();
        let contents =
            std::fs::read_to_string(path).map_err(|source| PegasusError::IoError {
                path: path.to_path_buf(),
                source,
            })?;
        toml::from_str(&contents).map_err(|e| PegasusError::CertificationError {
            standard: path.display().to_string(),
            reason: format!("failed to parse profile: {}", e),
        })
    }

    /// Evaluate policy results against this certification profile's controls.
    pub fn evaluate(&self, policy_results: &[PolicyEvaluationResult]) -> CertificationResult {
        let control_results: Vec<ControlResult> = self
            .controls
            .iter()
            .map(|control| {
                let policy_decisions: Vec<(String, String)> = control
                    .policies
                    .iter()
                    .map(|policy_id| {
                        let decision = policy_results
                            .iter()
                            .find(|r| r.policy_id.0.contains(policy_id))
                            .map(|r| format!("{:?}", r.decision).to_lowercase())
                            .unwrap_or_else(|| "not_evaluated".to_string());
                        (policy_id.clone(), decision)
                    })
                    .collect();

                let required = &control.required_decision;
                let passed = policy_decisions.iter().all(|(_, decision)| {
                    decision == required || decision == "skip"
                    // skip = not enough input, not a failure
                });

                ControlResult {
                    id: control.id.clone(),
                    title: control.title.clone(),
                    passed,
                    severity: control.severity.clone(),
                    policy_decisions,
                }
            })
            .collect();

        let mut result = CertificationResult::from_controls(
            control_results,
            self.certification.pass_threshold,
            self.certification.critical_must_pass,
        );
        result.standard_id = self.certification.id.clone();
        result.standard_name = self.certification.name.clone();
        result
    }
}
