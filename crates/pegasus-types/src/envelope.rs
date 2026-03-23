use crate::types::{CollectorId, DataClassification, EvidenceEnvelope, EvidenceHash, Target};
use serde::Deserializer;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

impl EvidenceEnvelope {
    pub fn new(
        raw_payload: serde_json::Value,
        collected_at: chrono::DateTime<chrono::Utc>,
        collector_id: CollectorId,
        target: Target,
        classification: DataClassification,
        schema_version: semver::Version,
    ) -> Self {
        let hash = compute_content_hash(&raw_payload, &collected_at, &collector_id, &target);
        Self {
            hash,
            raw_payload,
            collected_at,
            collector_id,
            target,
            classification,
            schema_version,
        }
    }

    pub fn hash(&self) -> &EvidenceHash {
        &self.hash
    }
}

impl EvidenceHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn compute_content_hash(
    raw_payload: &serde_json::Value,
    collected_at: &chrono::DateTime<chrono::Utc>,
    collector_id: &CollectorId,
    target: &Target,
) -> EvidenceHash {
    let mut map: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    map.insert(
        "collected_at".to_string(),
        serde_json::Value::String(collected_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
    );
    map.insert(
        "collector_id".to_string(),
        serde_json::Value::String(collector_id.0.clone()),
    );
    map.insert("raw_payload".to_string(), raw_payload.clone());
    map.insert(
        "target".to_string(),
        serde_json::to_value(target).expect("Target serialization is infallible"),
    );

    let canonical =
        serde_json::to_string(&map).expect("BTreeMap<String, Value> serialization is infallible");

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let result = hasher.finalize();

    let hex: String = result.iter().map(|b| format!("{:02x}", b)).collect();
    EvidenceHash(hex)
}

// Custom Deserialize for EvidenceEnvelope.
//
// The derived Deserialize would allow a caller to supply an arbitrary `hash` field in
// the JSON payload, silently bypassing the invariant that the hash must always be
// computed from the content fields.  This custom implementation deserializes into a
// helper struct that has no `hash` field and then re-derives the hash via
// `compute_content_hash`, so the serialized hash value is always ignored and
// recomputed from the canonical content.
#[derive(serde::Deserialize)]
struct EvidenceEnvelopeData {
    raw_payload: serde_json::Value,
    collected_at: chrono::DateTime<chrono::Utc>,
    collector_id: CollectorId,
    target: Target,
    classification: DataClassification,
    schema_version: semver::Version,
}

impl<'de> serde::Deserialize<'de> for EvidenceEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = EvidenceEnvelopeData::deserialize(deserializer)?;
        let hash = compute_content_hash(
            &data.raw_payload,
            &data.collected_at,
            &data.collector_id,
            &data.target,
        );
        Ok(EvidenceEnvelope {
            hash,
            raw_payload: data.raw_payload,
            collected_at: data.collected_at,
            collector_id: data.collector_id,
            target: data.target,
            classification: data.classification,
            schema_version: data.schema_version,
        })
    }
}
