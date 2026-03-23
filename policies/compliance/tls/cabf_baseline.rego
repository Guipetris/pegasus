package compliance.tls.cabf_baseline

import rego.v1

default decision := "skip"
default reason := "insufficient input: required certificate fields not present"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# 398 days expressed in nanoseconds (the CA/Browser Forum max validity limit)
max_validity_ns := 398 * 24 * 60 * 60 * 1000000000

# 365 days in nanoseconds (lower bound of the "approaching limit" warn window)
warn_validity_ns := 365 * 24 * 60 * 60 * 1000000000

# Minimum key sizes per algorithm
min_rsa_bits := 2048
min_ec_bits := 256

# ---------------------------------------------------------------------------
# Root CA identification
# A certificate is a self-signed root CA when is_ca==true AND subject==issuer.
# Root CAs are exempt from the 398-day validity cap and SHA-1 restrictions.
# ---------------------------------------------------------------------------

is_root_ca(cert) if {
    cert.is_ca == true
    cert.subject == cert.issuer
}

# ---------------------------------------------------------------------------
# Non-CA certs (the certs we apply CAB Forum baseline rules to)
# ---------------------------------------------------------------------------

non_ca_certs := [cert |
    some cert in input.certificates
    cert.is_ca != true
]

# ---------------------------------------------------------------------------
# Validity duration helpers
# ---------------------------------------------------------------------------

cert_validity_ns(cert) := time.parse_rfc3339_ns(cert.not_after) - time.parse_rfc3339_ns(cert.not_before)

# ---------------------------------------------------------------------------
# Guard: skip unless we have certs and all non-CA certs have required fields
# ---------------------------------------------------------------------------

has_required_fields if {
    count(input.certificates) > 0
    every cert in non_ca_certs {
        cert.key_algorithm
        cert.key_size
    }
}

# ---------------------------------------------------------------------------
# Failure conditions on non-CA certs
# ---------------------------------------------------------------------------

any_validity_over_398 if {
    some cert in non_ca_certs
    cert_validity_ns(cert) > max_validity_ns
}

any_weak_key if {
    some cert in non_ca_certs
    cert.key_algorithm == "RSA"
    cert.key_size < min_rsa_bits
}

any_weak_key if {
    some cert in non_ca_certs
    cert.key_algorithm == "EC"
    cert.key_size < min_ec_bits
}

any_sha1_signature if {
    some cert in non_ca_certs
    contains(lower(cert.signature_algorithm), "sha1")
}

has_failure if {
    any_validity_over_398
}

has_failure if {
    any_weak_key
}

has_failure if {
    any_sha1_signature
}

# ---------------------------------------------------------------------------
# Warn condition: all certs OK but some are in the 365-398 day window
# ---------------------------------------------------------------------------

any_validity_approaching if {
    some cert in non_ca_certs
    v := cert_validity_ns(cert)
    v > warn_validity_ns
    v <= max_validity_ns
}

# ---------------------------------------------------------------------------
# Decision rules (evaluated in priority order: skip → fail → warn → pass)
# ---------------------------------------------------------------------------

decision := "fail" if {
    has_required_fields
    has_failure
}

decision := "warn" if {
    has_required_fields
    not has_failure
    any_validity_approaching
}

decision := "pass" if {
    has_required_fields
    not has_failure
    not any_validity_approaching
}

# ---------------------------------------------------------------------------
# Reason rules
# ---------------------------------------------------------------------------

reason := "all non-CA certificates meet CA/Browser Forum Baseline Requirements" if {
    decision == "pass"
}

reason := "all certificates compliant but some non-CA certificate validity is between 365 and 398 days (approaching the limit)" if {
    decision == "warn"
}

reason := "one or more non-CA certificates violate CA/Browser Forum Baseline Requirements: validity > 398 days, weak key (RSA < 2048 or EC < 256), or SHA-1 signature" if {
    decision == "fail"
}
