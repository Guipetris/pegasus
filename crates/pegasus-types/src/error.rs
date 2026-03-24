use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PegasusError {
    #[error("deserialization failed: {0}")]
    DeserializationError(#[from] serde_json::Error),
    #[error("invalid envelope: {reason}")]
    InvalidEnvelope { reason: String },
    #[error("I/O error at {path}: {source}")]
    IoError {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("store error: {reason}")]
    StoreError { reason: String },
    #[error("policy evaluation failed for {policy_id}: {reason}")]
    PolicyError { policy_id: String, reason: String },
    #[error("failed to load policy from {path}: {reason}")]
    PolicyLoadError { path: PathBuf, reason: String },
    #[error("certification error for {standard}: {reason}")]
    CertificationError { standard: String, reason: String },
    #[error("benchmark error: {reason}")]
    BenchmarkError { reason: String },
}
