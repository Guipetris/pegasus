package compliance.http.security_txt_present

import rego.v1

# Checks that the domain publishes a security.txt file (RFC 9116) at
# /.well-known/security.txt.
#
# Evidence input fields (from WellKnownProbeResult):
#   input.security_txt.found        bool
#   input.security_txt.contact      string | null
#   input.security_txt.is_expired   bool
#
# Decision logic:
#   skip — no well-known probe evidence in input
#   warn — security.txt is absent
#   warn — security.txt is present but expired
#   pass — security.txt is present, not expired, and has a Contact field
#   pass — security.txt is present, not expired (no Contact required to pass)
#
# Standards:
#   RFC 9116 — A File Format to Aid in Security Vulnerability Disclosure
#   ISO 27001 A.5.5 — Contact with special interest groups

default decision := "skip"
default reason := "no well-known probe evidence in input"

decision := "warn" if {
    object.get(input, "security_txt", null) != null
    object.get(input.security_txt, "found", null) != null
    input.security_txt.found == false
}

decision := "warn" if {
    object.get(input, "security_txt", null) != null
    input.security_txt.found == true
    input.security_txt.is_expired == true
}

decision := "pass" if {
    object.get(input, "security_txt", null) != null
    input.security_txt.found == true
    input.security_txt.is_expired == false
}

reason := "security.txt not found at /.well-known/security.txt — publish a security.txt to provide a clear vulnerability disclosure channel (RFC 9116)" if {
    decision == "warn"
    input.security_txt.found == false
}

reason := "security.txt found but the Expires field has passed — update the file to keep the disclosure policy active (RFC 9116 §2.5.5)" if {
    decision == "warn"
    input.security_txt.found == true
    input.security_txt.is_expired == true
}

reason := "security.txt found and not expired — vulnerability disclosure policy is publicly available" if {
    decision == "pass"
}
