package compliance.tls.sha1_signature_prohibition

import rego.v1

# Skip when there are no certificates or when the signature_algorithm field is absent.
# Root CAs (is_ca == true AND subject == issuer) are exempt from SHA-1 prohibition.

default decision := "skip"
default reason := "insufficient input: no certificates or signature_algorithm field not present"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# A certificate is a self-signed root CA.
is_root_ca(cert) if {
    cert.is_ca == true
    cert.subject == cert.issuer
}

# Non-root certs that have a signature_algorithm field.
non_root_certs_with_sig_algo := [cert |
    some cert in input.certificates
    not is_root_ca(cert)
    cert.signature_algorithm
]

# Guard: we have at least one certificate AND at least one non-root cert has the field.
has_required_fields if {
    count(input.certificates) > 0
    count(non_root_certs_with_sig_algo) > 0
}

# Fail condition: any non-root cert signed with SHA-1.
any_sha1_non_root if {
    some cert in non_root_certs_with_sig_algo
    contains(lower(cert.signature_algorithm), "sha1")
}

# ---------------------------------------------------------------------------
# Decision rules
# ---------------------------------------------------------------------------

decision := "fail" if {
    has_required_fields
    any_sha1_non_root
}

decision := "pass" if {
    has_required_fields
    not any_sha1_non_root
}

# ---------------------------------------------------------------------------
# Reason messages
# ---------------------------------------------------------------------------

reason := "no non-root certificates use SHA-1 signature algorithm" if {
    decision == "pass"
}

reason := "one or more non-root certificates use a SHA-1 signature algorithm, which is prohibited" if {
    decision == "fail"
}
