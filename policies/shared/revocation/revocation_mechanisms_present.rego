package shared.revocation.revocation_mechanisms_present

import rego.v1

# Checks that a TLS certificate advertises at least one revocation mechanism
# (OCSP responder URL or CRL Distribution Points).
#
# Evidence input fields (from RevocationProbeResult):
#   input.has_ocsp_responder            bool
#   input.has_crl_distribution_points   bool
#   input.revocation_mechanisms_count   integer (0–2)
#
# Decision logic:
#   skip — no revocation probe evidence in input
#   fail — no revocation mechanisms present (count == 0)
#   warn — only one mechanism present (OCSP or CRL, not both)
#   pass — both OCSP and CRL mechanisms present
#
# Standards: CA/Browser Forum BRs §4.9/4.10, NIST SP 800-52r2 §3.6

default decision := "skip"
default reason := "no revocation probe evidence in input"

decision := "fail" if {
    object.get(input, "revocation_mechanisms_count", null) != null
    input.revocation_mechanisms_count == 0
}

decision := "warn" if {
    object.get(input, "revocation_mechanisms_count", null) != null
    input.revocation_mechanisms_count == 1
}

decision := "pass" if {
    object.get(input, "revocation_mechanisms_count", null) != null
    input.revocation_mechanisms_count >= 2
}

reason := "Certificate advertises no revocation mechanisms — neither an OCSP responder URL nor CRL Distribution Points are present (CA/B Forum BRs §4.9/4.10)" if {
    decision == "fail"
}

reason := sprintf("Certificate advertises only one revocation mechanism (OCSP: %v, CRL: %v) — prefer both for resilience", [input.has_ocsp_responder, input.has_crl_distribution_points]) if {
    decision == "warn"
}

reason := "Certificate advertises both OCSP and CRL revocation mechanisms" if {
    decision == "pass"
}
