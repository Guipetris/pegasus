//! Change detection — compare current check against previous evidence for the same target.
//!
//! Surfaces what changed between checks: new certificates, expired certs, headers added/removed,
//! CAA record changes. This is the foundation for continuous monitoring alerts.

use pegasus_types::types::{ComplianceReport, PolicyDecision};

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChangeReport {
    pub target: String,
    pub previous_check_at: Option<String>,
    pub current_check_at: String,
    pub changes: Vec<Change>,
    pub regression_count: usize,
    pub improvement_count: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Change {
    pub policy_id: String,
    pub change_type: ChangeType,
    pub previous_decision: Option<String>,
    pub current_decision: String,
    pub detail: String,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub enum ChangeType {
    Regression,   // was Pass/Warn, now Fail/Error
    Improvement,  // was Fail/Error, now Pass/Warn
    New,          // policy didn't exist in previous check
    Unchanged,    // same decision
    StatusChange, // different decision but same severity tier
}

/// Compare two compliance reports and produce a change report.
pub fn diff_reports(previous: &ComplianceReport, current: &ComplianceReport) -> ChangeReport {
    let mut changes = Vec::new();

    for current_result in &current.results {
        let prev_result = previous
            .results
            .iter()
            .find(|r| r.policy_id == current_result.policy_id);

        match prev_result {
            Some(prev) => {
                if prev.decision != current_result.decision {
                    let change_type = classify_change(&prev.decision, &current_result.decision);
                    changes.push(Change {
                        policy_id: current_result.policy_id.0.clone(),
                        change_type,
                        previous_decision: Some(format!("{:?}", prev.decision)),
                        current_decision: format!("{:?}", current_result.decision),
                        detail: format!("Was: {} | Now: {}", prev.reason, current_result.reason),
                    });
                }
            }
            None => {
                changes.push(Change {
                    policy_id: current_result.policy_id.0.clone(),
                    change_type: ChangeType::New,
                    previous_decision: None,
                    current_decision: format!("{:?}", current_result.decision),
                    detail: current_result.reason.clone(),
                });
            }
        }
    }

    let regression_count = changes
        .iter()
        .filter(|c| c.change_type == ChangeType::Regression)
        .count();
    let improvement_count = changes
        .iter()
        .filter(|c| c.change_type == ChangeType::Improvement)
        .count();

    ChangeReport {
        target: current.target.uri.to_string(),
        previous_check_at: Some(previous.generated_at.to_rfc3339()),
        current_check_at: current.generated_at.to_rfc3339(),
        changes,
        regression_count,
        improvement_count,
    }
}

fn classify_change(prev: &PolicyDecision, curr: &PolicyDecision) -> ChangeType {
    let prev_severity = decision_severity(prev);
    let curr_severity = decision_severity(curr);

    if curr_severity > prev_severity {
        ChangeType::Regression
    } else if curr_severity < prev_severity {
        ChangeType::Improvement
    } else {
        ChangeType::StatusChange
    }
}

/// Higher = worse. Pass=0, Skip=0, Warn=1, Fail=2, Error=2
fn decision_severity(d: &PolicyDecision) -> u8 {
    match d {
        PolicyDecision::Pass | PolicyDecision::Skip => 0,
        PolicyDecision::Warn => 1,
        PolicyDecision::Fail | PolicyDecision::Error => 2,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use pegasus_types::types::{
        ComplianceReport, ComplianceVerdict, EvidenceHash, PolicyDecision, PolicyEvaluationResult,
        PolicyId, Target,
    };
    use url::Url;

    fn make_report(results: Vec<PolicyEvaluationResult>) -> ComplianceReport {
        ComplianceReport {
            report_id: "test-id".to_string(),
            verdict: ComplianceVerdict::Compliant,
            results,
            generated_at: Utc::now(),
            target: Target {
                uri: Url::parse("https://example.com").unwrap(),
                digest: None,
                label: None,
            },
            schema_version: semver::Version::new(1, 0, 0),
        }
    }

    fn make_result(policy: &str, decision: PolicyDecision, reason: &str) -> PolicyEvaluationResult {
        PolicyEvaluationResult {
            policy_id: PolicyId(policy.to_string()),
            decision,
            reason: reason.to_string(),
            evaluated_at: Utc::now(),
            evidence_hash: EvidenceHash("a".repeat(64)),
            metadata: None,
        }
    }

    #[test]
    fn no_changes_when_decisions_identical() {
        let result = make_result("tls/expiry", PolicyDecision::Pass, "cert valid");
        let prev = make_report(vec![result.clone()]);
        let curr = make_report(vec![result]);

        let report = diff_reports(&prev, &curr);
        assert_eq!(report.changes.len(), 0);
        assert_eq!(report.regression_count, 0);
        assert_eq!(report.improvement_count, 0);
    }

    #[test]
    fn regression_detected_pass_to_fail() {
        let prev_result = make_result("tls/expiry", PolicyDecision::Pass, "cert valid");
        let curr_result = make_result("tls/expiry", PolicyDecision::Fail, "cert expired");
        let prev = make_report(vec![prev_result]);
        let curr = make_report(vec![curr_result]);

        let report = diff_reports(&prev, &curr);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.changes[0].change_type, ChangeType::Regression);
        assert_eq!(report.regression_count, 1);
        assert_eq!(report.improvement_count, 0);
    }

    #[test]
    fn improvement_detected_fail_to_pass() {
        let prev_result = make_result("tls/expiry", PolicyDecision::Fail, "cert expired");
        let curr_result = make_result("tls/expiry", PolicyDecision::Pass, "cert valid");
        let prev = make_report(vec![prev_result]);
        let curr = make_report(vec![curr_result]);

        let report = diff_reports(&prev, &curr);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.changes[0].change_type, ChangeType::Improvement);
        assert_eq!(report.regression_count, 0);
        assert_eq!(report.improvement_count, 1);
    }

    #[test]
    fn new_policy_detected() {
        let prev = make_report(vec![]);
        let curr_result = make_result("tls/hsts", PolicyDecision::Pass, "HSTS present");
        let curr = make_report(vec![curr_result]);

        let report = diff_reports(&prev, &curr);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.changes[0].change_type, ChangeType::New);
        assert!(report.changes[0].previous_decision.is_none());
    }

    #[test]
    fn status_change_same_severity_tier() {
        // Pass → Skip: both severity 0, same tier
        let prev_result = make_result("tls/expiry", PolicyDecision::Pass, "pass");
        let curr_result = make_result("tls/expiry", PolicyDecision::Skip, "skipped");
        let prev = make_report(vec![prev_result]);
        let curr = make_report(vec![curr_result]);

        let report = diff_reports(&prev, &curr);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.changes[0].change_type, ChangeType::StatusChange);
    }

    #[test]
    fn warn_to_fail_is_regression() {
        let prev_result = make_result("tls/hsts", PolicyDecision::Warn, "weak HSTS");
        let curr_result = make_result("tls/hsts", PolicyDecision::Fail, "no HSTS");
        let prev = make_report(vec![prev_result]);
        let curr = make_report(vec![curr_result]);

        let report = diff_reports(&prev, &curr);
        assert_eq!(report.changes[0].change_type, ChangeType::Regression);
    }

    #[test]
    fn error_to_warn_is_improvement() {
        let prev_result = make_result("tls/chain", PolicyDecision::Error, "chain error");
        let curr_result = make_result("tls/chain", PolicyDecision::Warn, "chain warning");
        let prev = make_report(vec![prev_result]);
        let curr = make_report(vec![curr_result]);

        let report = diff_reports(&prev, &curr);
        assert_eq!(report.changes[0].change_type, ChangeType::Improvement);
    }

    #[test]
    fn classify_change_severity_table() {
        // Pass/Skip = 0, Warn = 1, Fail/Error = 2
        assert_eq!(
            classify_change(&PolicyDecision::Pass, &PolicyDecision::Fail),
            ChangeType::Regression
        );
        assert_eq!(
            classify_change(&PolicyDecision::Fail, &PolicyDecision::Pass),
            ChangeType::Improvement
        );
        assert_eq!(
            classify_change(&PolicyDecision::Fail, &PolicyDecision::Error),
            ChangeType::StatusChange
        );
        assert_eq!(
            classify_change(&PolicyDecision::Pass, &PolicyDecision::Skip),
            ChangeType::StatusChange
        );
        assert_eq!(
            classify_change(&PolicyDecision::Warn, &PolicyDecision::Pass),
            ChangeType::Improvement
        );
        assert_eq!(
            classify_change(&PolicyDecision::Pass, &PolicyDecision::Warn),
            ChangeType::Regression
        );
    }
}
