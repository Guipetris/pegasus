//! Cross-review: runs both security (Bellerophon) and compliance (Pegasus) scans,
//! compares findings, and produces a confidence-scored review.

use serde::Serialize;

use pegasus_types::types::{ComplianceVerdict, PolicyDecision, PolicyEvaluationResult};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Result of a cross-review combining security and compliance scan outputs.
#[derive(Debug, Serialize)]
pub struct CrossReviewResult {
    pub security_verdict: ComplianceVerdict,
    pub compliance_verdict: ComplianceVerdict,
    pub overall_verdict: ComplianceVerdict,
    /// Fraction of shared policies where both agents agreed (0.0–1.0).
    /// 1.0 when there are no shared policies.
    pub confidence: f64,
    pub security_result_count: usize,
    pub compliance_result_count: usize,
    pub shared_agreements: Vec<AgreementDetail>,
}

/// Per-policy agreement detail for policies evaluated by both agents.
#[derive(Debug, Serialize)]
pub struct AgreementDetail {
    pub policy_name: String,
    pub security_decision: Option<PolicyDecision>,
    pub compliance_decision: Option<PolicyDecision>,
    pub agrees: bool,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Combine security and compliance scan results into a cross-reviewed verdict.
pub fn cross_review(
    security_results: &[PolicyEvaluationResult],
    compliance_results: &[PolicyEvaluationResult],
) -> CrossReviewResult {
    let security_verdict = aggregate_verdict(security_results);
    let compliance_verdict = aggregate_verdict(compliance_results);

    // Overall verdict is the worst of the two individual verdicts.
    let overall_verdict = worst_verdict(&security_verdict, &compliance_verdict);

    // Find shared policies (same leaf name in both sets) and check agreement.
    let shared_agreements = find_agreements(security_results, compliance_results);

    let agreeing = shared_agreements.iter().filter(|a| a.agrees).count();
    let total_shared = shared_agreements.len();
    let confidence = if total_shared == 0 {
        1.0
    } else {
        agreeing as f64 / total_shared as f64
    };

    CrossReviewResult {
        security_verdict,
        compliance_verdict,
        overall_verdict,
        confidence,
        security_result_count: security_results.len(),
        compliance_result_count: compliance_results.len(),
        shared_agreements,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Aggregate a slice of policy results into a single compliance verdict.
///
/// NonCompliant if any Fail/Error; Degraded if any Warn; Compliant otherwise.
pub fn aggregate_verdict(results: &[PolicyEvaluationResult]) -> ComplianceVerdict {
    let mut has_warn = false;

    for r in results {
        match r.decision {
            PolicyDecision::Fail | PolicyDecision::Error => {
                return ComplianceVerdict::NonCompliant;
            }
            PolicyDecision::Warn => {
                has_warn = true;
            }
            PolicyDecision::Pass | PolicyDecision::Skip => {}
        }
    }

    if has_warn {
        ComplianceVerdict::Degraded
    } else {
        ComplianceVerdict::Compliant
    }
}

/// Return the more severe of two verdicts.
///
/// Severity order: NonCompliant > Degraded > Compliant.
fn worst_verdict(a: &ComplianceVerdict, b: &ComplianceVerdict) -> ComplianceVerdict {
    match (a, b) {
        (ComplianceVerdict::NonCompliant, _) | (_, ComplianceVerdict::NonCompliant) => {
            ComplianceVerdict::NonCompliant
        }
        (ComplianceVerdict::Degraded, _) | (_, ComplianceVerdict::Degraded) => {
            ComplianceVerdict::Degraded
        }
        _ => ComplianceVerdict::Compliant,
    }
}

/// Match policies by their leaf name (last path segment of `policy_id.0`) and
/// compare decisions to determine agreement.
fn find_agreements(
    security_results: &[PolicyEvaluationResult],
    compliance_results: &[PolicyEvaluationResult],
) -> Vec<AgreementDetail> {
    // Build a lookup from leaf name → decision for each side.
    let security_map: std::collections::HashMap<String, &PolicyDecision> = security_results
        .iter()
        .map(|r| (leaf_name(&r.policy_id.0), &r.decision))
        .collect();

    let compliance_map: std::collections::HashMap<String, &PolicyDecision> = compliance_results
        .iter()
        .map(|r| (leaf_name(&r.policy_id.0), &r.decision))
        .collect();

    // Collect all leaf names that appear in both sets.
    let mut shared_names: Vec<String> = security_map
        .keys()
        .filter(|name| compliance_map.contains_key(*name))
        .cloned()
        .collect();
    shared_names.sort();

    shared_names
        .into_iter()
        .map(|name| {
            let sec_decision = security_map.get(&name).copied().cloned();
            let comp_decision = compliance_map.get(&name).copied().cloned();
            let agrees = sec_decision == comp_decision;
            AgreementDetail {
                policy_name: name,
                security_decision: sec_decision,
                compliance_decision: comp_decision,
                agrees,
            }
        })
        .collect()
}

/// Extract the leaf name from a policy ID path (last `/`-separated segment).
fn leaf_name(policy_id: &str) -> String {
    policy_id
        .rsplit('/')
        .next()
        .unwrap_or(policy_id)
        .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use pegasus_types::types::{EvidenceHash, PolicyDecision, PolicyEvaluationResult, PolicyId};

    fn make_result(id: &str, decision: PolicyDecision) -> PolicyEvaluationResult {
        PolicyEvaluationResult {
            policy_id: PolicyId(id.to_string()),
            decision,
            reason: "test".to_string(),
            evaluated_at: Utc::now(),
            evidence_hash: EvidenceHash("a".repeat(64)),
            metadata: None,
        }
    }

    #[test]
    fn worst_verdict_noncompliant_wins() {
        assert_eq!(
            worst_verdict(
                &ComplianceVerdict::NonCompliant,
                &ComplianceVerdict::Compliant
            ),
            ComplianceVerdict::NonCompliant
        );
        assert_eq!(
            worst_verdict(
                &ComplianceVerdict::Compliant,
                &ComplianceVerdict::NonCompliant
            ),
            ComplianceVerdict::NonCompliant
        );
        assert_eq!(
            worst_verdict(
                &ComplianceVerdict::Degraded,
                &ComplianceVerdict::NonCompliant
            ),
            ComplianceVerdict::NonCompliant
        );
    }

    #[test]
    fn worst_verdict_degraded_beats_compliant() {
        assert_eq!(
            worst_verdict(&ComplianceVerdict::Degraded, &ComplianceVerdict::Compliant),
            ComplianceVerdict::Degraded
        );
        assert_eq!(
            worst_verdict(&ComplianceVerdict::Compliant, &ComplianceVerdict::Degraded),
            ComplianceVerdict::Degraded
        );
    }

    #[test]
    fn worst_verdict_both_compliant() {
        assert_eq!(
            worst_verdict(&ComplianceVerdict::Compliant, &ComplianceVerdict::Compliant),
            ComplianceVerdict::Compliant
        );
    }

    #[test]
    fn cross_review_no_shared_policies_confidence_is_1() {
        let sec = vec![make_result("security/tls/cipher", PolicyDecision::Pass)];
        let comp = vec![make_result("compliance/tls/cabf", PolicyDecision::Pass)];
        let result = cross_review(&sec, &comp);
        assert_eq!(result.confidence, 1.0);
        assert!(result.shared_agreements.is_empty());
    }

    #[test]
    fn cross_review_shared_agreement() {
        let sec = vec![make_result("shared/tls/cert_valid", PolicyDecision::Pass)];
        let comp = vec![make_result("shared/tls/cert_valid", PolicyDecision::Pass)];
        let result = cross_review(&sec, &comp);
        assert_eq!(result.confidence, 1.0);
        assert_eq!(result.shared_agreements.len(), 1);
        assert!(result.shared_agreements[0].agrees);
    }

    #[test]
    fn cross_review_shared_disagreement() {
        let sec = vec![make_result("shared/tls/cert_valid", PolicyDecision::Pass)];
        let comp = vec![make_result("shared/tls/cert_valid", PolicyDecision::Fail)];
        let result = cross_review(&sec, &comp);
        assert_eq!(result.confidence, 0.0);
        assert!(!result.shared_agreements[0].agrees);
    }

    #[test]
    fn cross_review_overall_is_worst() {
        let sec = vec![make_result("security/cipher", PolicyDecision::Fail)];
        let comp = vec![make_result("compliance/cabf", PolicyDecision::Pass)];
        let result = cross_review(&sec, &comp);
        assert_eq!(result.overall_verdict, ComplianceVerdict::NonCompliant);
        assert_eq!(result.security_verdict, ComplianceVerdict::NonCompliant);
        assert_eq!(result.compliance_verdict, ComplianceVerdict::Compliant);
    }

    #[test]
    fn leaf_name_extracts_last_segment() {
        assert_eq!(leaf_name("shared/tls/cert_valid"), "cert_valid");
        assert_eq!(leaf_name("cert_valid"), "cert_valid");
        assert_eq!(leaf_name("a/b/c/d"), "d");
    }
}
