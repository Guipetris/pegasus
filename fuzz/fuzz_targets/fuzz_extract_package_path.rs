#![no_main]

use libfuzzer_sys::fuzz_target;
use pegasus_policy::extract_package_path;

fuzz_target!(|data: &[u8]| {
    // Fuzz Rego package declaration extraction.
    // Exercises line splitting, prefix matching, and character validation
    // against arbitrary byte sequences.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = extract_package_path(s);
    }
});
