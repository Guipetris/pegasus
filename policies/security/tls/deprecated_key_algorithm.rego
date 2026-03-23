package security.tls.deprecated_key_algorithm

import rego.v1

# Skip when no certificate has a key_algorithm field.
# Fail if any certificate uses DSA — deprecated and considered cryptographically unsafe.
# Pass otherwise.

default decision := "skip"
default reason := "insufficient input: no key_algorithm fields present in certificates"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Certs that have a key_algorithm field.
certs_with_key_algo := [cert |
    some cert in input.certificates
    cert.key_algorithm
]

# Guard: at least one cert must have key_algorithm present.
has_required_fields if {
    count(certs_with_key_algo) > 0
}

# Fail condition: any cert uses DSA.
any_dsa_cert if {
    some cert in certs_with_key_algo
    cert.key_algorithm == "DSA"
}

# ---------------------------------------------------------------------------
# Decision rules
# ---------------------------------------------------------------------------

decision := "fail" if {
    has_required_fields
    any_dsa_cert
}

decision := "pass" if {
    has_required_fields
    not any_dsa_cert
}

# ---------------------------------------------------------------------------
# Reason messages
# ---------------------------------------------------------------------------

reason := "no certificates use deprecated key algorithms" if {
    decision == "pass"
}

reason := "one or more certificates use DSA, which is deprecated and must not be used" if {
    decision == "fail"
}
