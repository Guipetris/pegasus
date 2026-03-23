package compliance.tls.wildcard_detection

import rego.v1

# Skip when certificates are absent.
# Warn if any leaf (non-CA) certificate subject contains a wildcard ("*.").
# Pass if no leaf certificates have wildcards.

default decision := "skip"
default reason := "insufficient input: no certificates present"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Guard: at least one certificate must be present.
has_certificates if {
    count(input.certificates) > 0
}

# Leaf certificates (non-CA).
leaf_certs := [cert |
    some cert in input.certificates
    cert.is_ca != true
]

# Any leaf cert has a wildcard subject.
any_wildcard_leaf if {
    some cert in leaf_certs
    contains(cert.subject, "*.")
}

# ---------------------------------------------------------------------------
# Decision rules
# ---------------------------------------------------------------------------

decision := "warn" if {
    has_certificates
    any_wildcard_leaf
}

decision := "pass" if {
    has_certificates
    not any_wildcard_leaf
}

# ---------------------------------------------------------------------------
# Reason messages
# ---------------------------------------------------------------------------

reason := "no wildcard certificates detected in the chain" if {
    decision == "pass"
}

reason := "wildcard certificate detected: wildcard certs reduce auditability and increase blast radius on key compromise" if {
    decision == "warn"
}
