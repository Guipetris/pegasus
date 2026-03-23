package security.ct.unexpected_certificates

import rego.v1

# Detects certificates issued by CAs not on the trusted issuer allowlist.
#
# Evidence input fields (from CtProbeResult):
#   input.unexpected_issuers  bool   — true if any issuer is not in the allowlist
#   input.total_count         number — total deduplicated cert entries found
#
# Standards: CA/Browser Forum Baseline Requirements v2 §8.6, RFC 9162 §8

default decision := "skip"
default reason := "no Certificate Transparency evidence in input"

decision := "fail" if {
    object.get(input, "unexpected_issuers", null) != null
    input.unexpected_issuers == true
}

decision := "pass" if {
    object.get(input, "unexpected_issuers", null) != null
    input.unexpected_issuers == false
}

reason := "One or more certificates were issued by an unexpected CA not in the trusted issuer allowlist — investigate for possible misissuance" if {
    decision == "fail"
}

reason := "All certificate issuers are within the trusted CA allowlist" if {
    decision == "pass"
}
