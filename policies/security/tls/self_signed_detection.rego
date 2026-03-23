package security.tls.self_signed_detection

import rego.v1

# Skip when certificates are absent.
# Fail if the chain contains exactly one certificate where issuer == subject
# but is_ca == false — a self-signed non-CA (a common misconfiguration).
# Pass if the chain has more than one certificate, or the single cert is a proper CA.

default decision := "skip"
default reason := "insufficient input: no certificates present"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Guard: at least one certificate must be present.
has_certificates if {
    count(input.certificates) > 0
}

# A single self-signed non-CA certificate is a misconfiguration.
is_self_signed_non_ca if {
    count(input.certificates) == 1
    input.certificates[0].subject == input.certificates[0].issuer
    input.certificates[0].is_ca != true
}

# ---------------------------------------------------------------------------
# Decision rules
# ---------------------------------------------------------------------------

decision := "fail" if {
    has_certificates
    is_self_signed_non_ca
}

decision := "pass" if {
    has_certificates
    not is_self_signed_non_ca
}

# ---------------------------------------------------------------------------
# Reason messages
# ---------------------------------------------------------------------------

reason := "no self-signed non-CA certificates detected" if {
    decision == "pass"
}

reason := "self-signed non-CA certificate detected: chain has only one cert with issuer == subject and is_ca != true" if {
    decision == "fail"
}
