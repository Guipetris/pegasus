package compliance.revocation.ocsp_responder_available

import rego.v1

# Checks that the leaf certificate includes an OCSP responder URL in its
# Authority Information Access (AIA) extension.
#
# Evidence input fields (from RevocationProbeResult):
#   input.has_ocsp_responder    bool
#   input.ocsp_responder_url    string | null
#
# Decision logic:
#   skip — no revocation probe evidence in input
#   fail — OCSP responder URL is absent
#   pass — OCSP responder URL is present
#
# Standards:
#   CA/Browser Forum BRs §4.9.9 — OCSP response requirements
#   NIST SP 800-52r2 §3.6 — Certificate revocation checking

default decision := "skip"
default reason := "no revocation probe evidence in input"

decision := "fail" if {
    object.get(input, "has_ocsp_responder", null) != null
    input.has_ocsp_responder == false
}

decision := "pass" if {
    object.get(input, "has_ocsp_responder", null) != null
    input.has_ocsp_responder == true
}

reason := "No OCSP responder URL found in certificate Authority Information Access extension — live revocation checking is not possible (CA/B Forum BRs §4.9.9)" if {
    decision == "fail"
}

reason := sprintf("OCSP responder URL present: %v", [input.ocsp_responder_url]) if {
    decision == "pass"
}
