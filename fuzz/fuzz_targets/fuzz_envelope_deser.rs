#![no_main]

use libfuzzer_sys::fuzz_target;
use pegasus_types::types::EvidenceEnvelope;

fuzz_target!(|data: &[u8]| {
    // Fuzz the custom Deserialize impl for EvidenceEnvelope.
    // This exercises JSON parsing, DateTime<Utc> parsing, URL validation,
    // semver parsing, and the SHA-256 content-hash recomputation invariant.
    let _ = serde_json::from_slice::<EvidenceEnvelope>(data);
});
