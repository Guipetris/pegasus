package compliance.tls.hostname_validation

import rego.v1

# Skip when target_host is not present in input or when certificates are absent.
# This field may not yet exist in older evidence — graceful skip is required.
# Warn if the leaf certificate subject does not contain the target hostname.

default decision := "skip"
default reason := "insufficient input: target_host or certificates not present"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Leaf certificate: first cert in the chain (index 0), or the only cert.
leaf_cert := input.certificates[0]

# Guard: both target_host and at least one certificate must be present.
has_required_fields if {
    input.target_host
    count(input.certificates) > 0
}

# Match: subject contains the target hostname (case-insensitive).
hostname_matches if {
    contains(lower(leaf_cert.subject), lower(input.target_host))
}

# ---------------------------------------------------------------------------
# Decision rules
# ---------------------------------------------------------------------------

decision := "warn" if {
    has_required_fields
    not hostname_matches
}

decision := "pass" if {
    has_required_fields
    hostname_matches
}

# ---------------------------------------------------------------------------
# Reason messages
# ---------------------------------------------------------------------------

reason := "leaf certificate subject matches the target hostname" if {
    decision == "pass"
}

reason := "leaf certificate subject does not contain the target hostname — potential hostname mismatch" if {
    decision == "warn"
}
