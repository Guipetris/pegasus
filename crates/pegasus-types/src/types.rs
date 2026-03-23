use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

// Newtypes

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CollectorId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PolicyId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceHash(pub String);

// Enums

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum AttestationFormat {
    InToto,
    W3cVc,
    X509,
    Slsa,
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PolicyDecision {
    Pass,
    Fail,
    Warn,
    Error,
    Skip,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ComplianceVerdict {
    Compliant,
    NonCompliant,
    Degraded,
}

// Target

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Target {
    pub uri: Url,
    pub digest: Option<String>,
    pub label: Option<String>,
}

// EvidenceEnvelope

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct EvidenceEnvelope {
    pub(crate) hash: EvidenceHash,
    pub raw_payload: serde_json::Value,
    pub collected_at: DateTime<Utc>,
    pub collector_id: CollectorId,
    pub target: Target,
    pub classification: DataClassification,
    pub schema_version: semver::Version,
}

// AttestationRecord

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AttestationRecord {
    pub format: AttestationFormat,
    pub payload: serde_json::Value,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub issuer: String,
}

// PolicyEvaluationResult

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyEvaluationResult {
    pub policy_id: PolicyId,
    pub decision: PolicyDecision,
    pub reason: String,
    pub evaluated_at: DateTime<Utc>,
    pub evidence_hash: EvidenceHash,
    pub metadata: Option<serde_json::Value>,
}

// ComplianceReport

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ComplianceReport {
    pub report_id: String,
    pub verdict: ComplianceVerdict,
    pub results: Vec<PolicyEvaluationResult>,
    pub generated_at: DateTime<Utc>,
    pub target: Target,
    pub schema_version: semver::Version,
}
