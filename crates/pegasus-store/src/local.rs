use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::traits::EvidenceStore;
use pegasus_types::error::PegasusError;
use pegasus_types::types::{ComplianceReport, EvidenceEnvelope, EvidenceHash, Target};

/// A local filesystem-backed evidence store.
///
/// Blobs are stored under `{root}/{hash[0..2]}/{hash[2..]}.json` — the same
/// two-character prefix layout used by Git's object store — so that no single
/// directory accumulates an unbounded number of entries.
pub struct LocalFileStore {
    root: PathBuf,
}

impl LocalFileStore {
    /// Create a new `LocalFileStore` rooted at `root`.
    ///
    /// The directory is created (including parents) if it does not already
    /// exist.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, PegasusError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| PegasusError::IoError {
            path: root.clone(),
            source: e,
        })?;
        Ok(Self { root })
    }

    /// Derive the filesystem path for a compliance report keyed by target URI.
    ///
    /// Path: `{root}/reports/{sha256(target_uri)}.json`
    /// Using SHA-256 of the URI keeps filenames safe for all filesystems while
    /// remaining deterministic — one file per target, overwritten each check.
    fn report_path(&self, target_uri: &str) -> PathBuf {
        let hash = Sha256::digest(target_uri.as_bytes());
        let hex = format!("{:x}", hash);
        self.root.join("reports").join(format!("{}.json", hex))
    }

    /// Derive the filesystem path for a given hash.
    fn blob_path(&self, hash: &EvidenceHash) -> PathBuf {
        let hex = hash.as_str();
        // Guard against hashes shorter than 2 chars (should never happen in
        // practice with SHA-256 output but we handle it gracefully).
        let (prefix, rest) = if hex.len() >= 2 {
            hex.split_at(2)
        } else {
            ("00", hex)
        };
        self.root.join(prefix).join(format!("{}.json", rest))
    }
}

impl EvidenceStore for LocalFileStore {
    /// Serialize `envelope` to pretty JSON and persist it atomically.
    ///
    /// Atomicity is achieved via a sibling `.tmp` file followed by a rename.
    /// If a file with the same hash already exists the write is skipped so
    /// the operation is idempotent.
    fn store(&self, envelope: &EvidenceEnvelope) -> Result<EvidenceHash, PegasusError> {
        let hash = envelope.hash().clone();
        let dest = self.blob_path(&hash);

        // Idempotent: if already persisted, return early.
        if dest.exists() {
            return Ok(hash);
        }

        // Ensure the two-char prefix directory exists.
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| PegasusError::IoError {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let json = serde_json::to_string_pretty(envelope)?;

        // Write to a temp file next to the destination, then rename for
        // atomicity (rename is atomic on POSIX when src and dst are on the
        // same filesystem).
        let tmp_path = dest.with_extension("tmp");
        fs::write(&tmp_path, &json).map_err(|e| PegasusError::IoError {
            path: tmp_path.clone(),
            source: e,
        })?;
        fs::rename(&tmp_path, &dest).map_err(|e| PegasusError::IoError {
            path: dest.clone(),
            source: e,
        })?;

        Ok(hash)
    }

    /// Read and deserialize the envelope identified by `hash`.
    ///
    /// Returns `None` if no blob exists for that hash.
    fn retrieve(&self, hash: &EvidenceHash) -> Result<Option<EvidenceEnvelope>, PegasusError> {
        let path = self.blob_path(hash);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path).map_err(|e| PegasusError::IoError {
            path: path.clone(),
            source: e,
        })?;
        // The custom Deserialize impl recomputes the hash from content fields,
        // so any stored hash value is ignored and the invariant is preserved.
        let envelope: EvidenceEnvelope = serde_json::from_slice(&bytes)?;
        Ok(Some(envelope))
    }

    /// Return `true` if a blob file for `hash` already exists on disk.
    fn exists(&self, hash: &EvidenceHash) -> Result<bool, PegasusError> {
        Ok(self.blob_path(hash).exists())
    }

    /// Walk the store at depth 2 (blob files only), deserialize every
    /// envelope, and collect the hashes of those whose `target.uri` matches
    /// `target`.
    fn list_by_target(&self, target: &Target) -> Result<Vec<EvidenceHash>, PegasusError> {
        let mut hashes = Vec::new();

        for entry in walkdir::WalkDir::new(&self.root)
            .min_depth(2)
            .max_depth(2)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_type().is_file() && e.path().extension().is_some_and(|ext| ext == "json")
            })
        {
            let path = entry.path();
            let bytes = fs::read(path).map_err(|e| PegasusError::IoError {
                path: path.to_path_buf(),
                source: e,
            })?;
            match serde_json::from_slice::<EvidenceEnvelope>(&bytes) {
                Ok(envelope) => {
                    if envelope.target.uri == target.uri {
                        hashes.push(envelope.hash().clone());
                    }
                }
                Err(_) => {
                    // Skip files that cannot be deserialized (e.g. partially
                    // written blobs or unrelated JSON files that ended up in
                    // the store directory).
                }
            }
        }

        Ok(hashes)
    }

    /// Serialize `report` to JSON and write it to `reports/{target_hash}.json`.
    ///
    /// Uses atomic write (tmp + rename) consistent with `store()`. Overwrites
    /// any previous report for the same target.
    fn save_report(&self, report: &ComplianceReport) -> Result<(), PegasusError> {
        let dest = self.report_path(report.target.uri.as_str());

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| PegasusError::IoError {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let json = serde_json::to_string_pretty(report)?;
        let tmp_path = dest.with_extension("tmp");

        fs::write(&tmp_path, &json).map_err(|e| PegasusError::IoError {
            path: tmp_path.clone(),
            source: e,
        })?;
        fs::rename(&tmp_path, &dest).map_err(|e| PegasusError::IoError {
            path: dest.clone(),
            source: e,
        })?;

        Ok(())
    }

    /// Read and deserialize the most recent report for `target_uri`.
    ///
    /// Returns `None` if no report has been saved for this target yet.
    fn latest_report(&self, target_uri: &str) -> Result<Option<ComplianceReport>, PegasusError> {
        let path = self.report_path(target_uri);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path).map_err(|e| PegasusError::IoError {
            path: path.clone(),
            source: e,
        })?;
        let report: ComplianceReport = serde_json::from_slice(&bytes)?;
        Ok(Some(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pegasus_types::types::{CollectorId, DataClassification, EvidenceEnvelope, Target};
    use chrono::Utc;
    use url::Url;

    /// Create a unique temp directory under the system temp root for each test.
    fn tmp_dir(suffix: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "pegasus-tests-{}-{}",
            suffix,
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    fn make_envelope(uri: &str, payload_val: u64) -> EvidenceEnvelope {
        EvidenceEnvelope::new(
            serde_json::json!({ "v": payload_val }),
            Utc::now(),
            CollectorId("test-collector".to_string()),
            Target {
                uri: Url::parse(uri).unwrap(),
                digest: None,
                label: None,
            },
            DataClassification::Internal,
            semver::Version::new(1, 0, 0),
        )
    }

    #[test]
    fn store_and_retrieve_roundtrip() {
        let dir = tmp_dir("roundtrip");
        let store = LocalFileStore::new(&dir).unwrap();

        let envelope = make_envelope("https://example.com/repo", 42);
        let hash = store.store(&envelope).unwrap();

        assert!(store.exists(&hash).unwrap());
        let retrieved = store.retrieve(&hash).unwrap().expect("should exist");
        assert_eq!(retrieved.hash(), &hash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_is_idempotent() {
        let dir = tmp_dir("idempotent");
        let store = LocalFileStore::new(&dir).unwrap();

        let envelope = make_envelope("https://example.com/repo", 1);
        let h1 = store.store(&envelope).unwrap();
        let h2 = store.store(&envelope).unwrap();
        assert_eq!(h1, h2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retrieve_missing_returns_none() {
        let dir = tmp_dir("missing");
        let store = LocalFileStore::new(&dir).unwrap();
        let fake = EvidenceHash("a".repeat(64));
        assert!(store.retrieve(&fake).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_by_target_filters_correctly() {
        let dir = tmp_dir("list-by-target");
        let store = LocalFileStore::new(&dir).unwrap();

        let uri_a = "https://example.com/repo-a";
        let uri_b = "https://example.com/repo-b";

        let e1 = make_envelope(uri_a, 1);
        let e2 = make_envelope(uri_a, 2);
        let e3 = make_envelope(uri_b, 3);

        store.store(&e1).unwrap();
        store.store(&e2).unwrap();
        store.store(&e3).unwrap();

        let target_a = Target {
            uri: Url::parse(uri_a).unwrap(),
            digest: None,
            label: None,
        };
        let mut found = store.list_by_target(&target_a).unwrap();
        found.sort_by(|a, b| a.as_str().cmp(b.as_str()));

        assert_eq!(found.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
