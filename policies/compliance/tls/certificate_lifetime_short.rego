package compliance.tls.certificate_lifetime_short

import rego.v1

# Skip when no non-CA certificates have both not_before and not_after fields.
# Warn if any non-CA certificate has a validity period shorter than 30 days.
# Very short-lived certs may indicate misconfiguration or automation pipeline issues.

default decision := "skip"
default reason := "insufficient input: no non-CA certificates with not_before and not_after fields present"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# 30 days expressed in nanoseconds.
min_validity_ns := 30 * 24 * 60 * 60 * 1000000000

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Non-CA certs that have both date fields.
non_ca_certs_with_dates := [cert |
    some cert in input.certificates
    cert.is_ca != true
    cert.not_before
    cert.not_after
]

# Guard: at least one non-CA cert with date fields must exist.
has_required_fields if {
    count(non_ca_certs_with_dates) > 0
}

# Validity duration in nanoseconds for a cert.
cert_validity_ns(cert) := time.parse_rfc3339_ns(cert.not_after) - time.parse_rfc3339_ns(cert.not_before)

# Warn condition: any non-CA cert has validity < 30 days.
any_short_lifetime if {
    some cert in non_ca_certs_with_dates
    cert_validity_ns(cert) < min_validity_ns
}

# ---------------------------------------------------------------------------
# Decision rules
# ---------------------------------------------------------------------------

decision := "warn" if {
    has_required_fields
    any_short_lifetime
}

decision := "pass" if {
    has_required_fields
    not any_short_lifetime
}

# ---------------------------------------------------------------------------
# Reason messages
# ---------------------------------------------------------------------------

reason := "all non-CA certificates have a validity period of at least 30 days" if {
    decision == "pass"
}

reason := "one or more non-CA certificates have a validity period shorter than 30 days — verify automation pipeline" if {
    decision == "warn"
}
