use pegasus_types::error::PegasusError;
use pegasus_types::types::{ComplianceReport, EvidenceEnvelope, EvidenceHash, Target};

/// Pluggable storage backend for evidence envelopes.
pub trait EvidenceStore {
    fn store(&self, envelope: &EvidenceEnvelope) -> Result<EvidenceHash, PegasusError>;
    fn retrieve(&self, hash: &EvidenceHash) -> Result<Option<EvidenceEnvelope>, PegasusError>;
    fn exists(&self, hash: &EvidenceHash) -> Result<bool, PegasusError>;
    fn list_by_target(&self, target: &Target) -> Result<Vec<EvidenceHash>, PegasusError>;

    /// Save a compliance report for later comparison.
    ///
    /// Overwrites any previous report for the same target — we only need the
    /// most recent snapshot to compute diffs.
    fn save_report(&self, report: &ComplianceReport) -> Result<(), PegasusError>;

    /// Load the most recent report for a target URI.
    ///
    /// Returns `None` if this is the first check for the target.
    fn latest_report(&self, target_uri: &str) -> Result<Option<ComplianceReport>, PegasusError>;
}
