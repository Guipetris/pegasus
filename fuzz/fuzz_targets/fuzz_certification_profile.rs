#![no_main]

use libfuzzer_sys::fuzz_target;
use pegasus_certify::CertificationProfile;

fuzz_target!(|data: &[u8]| {
    // Fuzz TOML deserialization of certification profiles.
    // Exercises toml parser, float threshold parsing, enum-like severity
    // strings, and nested control arrays.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = toml::from_str::<CertificationProfile>(s);
    }
});
