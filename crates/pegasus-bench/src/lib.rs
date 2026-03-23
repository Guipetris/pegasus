//! Benchmark types, catalog loader, and verdict comparison for Pegasus.
//!
//! The `run_benchmark` runner (which performs live network probes) lives in
//! Bellerophon and is intentionally excluded from this crate.

use pegasus_types::error::PegasusError;
use serde::Deserialize;
use std::path::Path;

// ── Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TestCase {
    pub test: TestMeta,
    pub expected: ExpectedVerdict,
    #[serde(default)]
    pub metadata: Option<toml::Value>,
}

#[derive(Debug, Deserialize)]
pub struct TestMeta {
    pub id: String,
    pub target: String,
    pub description: String,
    pub category: String,
    #[serde(default)]
    pub standards: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExpectedVerdict {
    pub overall_verdict: String, // "compliant", "non-compliant", "degraded", "error"
    #[serde(default)]
    pub policies: std::collections::HashMap<String, String>,
}

#[derive(Debug, Default)]
pub struct BenchmarkResult {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub true_positives: usize,
    pub true_negatives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
}

impl BenchmarkResult {
    /// Accuracy = (TP + TN) / (TP + TN + FP + FN)
    pub fn accuracy(&self) -> f64 {
        let denom =
            self.true_positives + self.true_negatives + self.false_positives + self.false_negatives;
        if denom == 0 {
            return 1.0;
        }
        (self.true_positives + self.true_negatives) as f64 / denom as f64
    }

    /// FNR = FN / (FN + TP)
    pub fn false_negative_rate(&self) -> f64 {
        let denom = self.false_negatives + self.true_positives;
        if denom == 0 {
            return 0.0;
        }
        self.false_negatives as f64 / denom as f64
    }

    /// FPR = FP / (FP + TN)
    pub fn false_positive_rate(&self) -> f64 {
        let denom = self.false_positives + self.true_negatives;
        if denom == 0 {
            return 0.0;
        }
        self.false_positives as f64 / denom as f64
    }
}

// ── Catalog ────────────────────────────────────────────────────────────

pub struct BenchmarkCatalog {
    pub test_cases: Vec<TestCase>,
}

impl BenchmarkCatalog {
    /// Load all .toml test case files from a directory tree.
    pub fn from_directory(dir: impl AsRef<Path>) -> Result<Self, PegasusError> {
        let dir = dir.as_ref();
        let mut test_cases = Vec::new();

        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            // Skip manifest.toml
            if path.file_name().and_then(|s| s.to_str()) == Some("manifest.toml") {
                continue;
            }

            let contents =
                std::fs::read_to_string(path).map_err(|source| PegasusError::IoError {
                    path: path.to_path_buf(),
                    source,
                })?;

            let case: TestCase =
                toml::from_str(&contents).map_err(|e| PegasusError::BenchmarkError {
                    reason: format!("failed to parse {}: {}", path.display(), e),
                })?;

            test_cases.push(case);
        }

        if test_cases.is_empty() {
            return Err(PegasusError::BenchmarkError {
                reason: format!("no .toml test cases found in {}", dir.display()),
            });
        }

        Ok(Self { test_cases })
    }
}

// ── Verdict comparison ─────────────────────────────────────────────────

/// Compare an actual verdict string against expected.
/// Returns: (matches, is_positive_case)
/// A "positive" case is one where we expect non-compliance (the tool should flag it).
pub fn compare_verdict(actual: &str, expected: &str) -> (bool, bool) {
    // Normalize: remove hyphens and lowercase (handles "non-compliant" vs "noncompliant")
    let normalize = |s: &str| s.to_lowercase().replace('-', "");
    let actual_norm = normalize(actual);
    let expected_norm = normalize(expected);
    let matches = actual_norm == expected_norm;
    let is_positive = expected_norm != "compliant"; // non-compliant/degraded/error = positive case
    (matches, is_positive)
}

// ── Per-case result ────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
pub struct TestCaseResult {
    pub id: String,
    pub target: String,
    pub expected: String,
    pub actual: String,
    pub matches: bool,
    pub error: Option<String>,
}
