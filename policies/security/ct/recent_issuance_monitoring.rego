package security.ct.recent_issuance_monitoring

import rego.v1

# Monitors for unusually high certificate issuance rates in the last 90 days.
#
# Evidence input fields (from CtProbeResult):
#   input.recent_cert_count  number — certs issued in the last 90 days
#   input.total_count        number — total deduplicated cert count
#
# Decision logic:
#   skip — no CT evidence present (non-web domain or probe did not run)
#   warn — recent_cert_count > 5 (high issuance rate, possible abuse)
#   pass — recent_cert_count <= 5 and total_count > 0
#
# Standards: RFC 9162 §8

default decision := "skip"
default reason := "no Certificate Transparency evidence in input"

decision := "warn" if {
    object.get(input, "total_count", null) != null
    input.total_count > 0
    input.recent_cert_count > 5
}

decision := "pass" if {
    object.get(input, "total_count", null) != null
    input.total_count > 0
    input.recent_cert_count <= 5
}

# skip when total_count == 0 — could be a non-web domain; do not alert
decision := "skip" if {
    object.get(input, "total_count", null) != null
    input.total_count == 0
}

reason := sprintf(
    "Unusually high certificate issuance rate: %d certs issued in the last 90 days — review for possible abuse or automated issuance",
    [input.recent_cert_count],
) if {
    decision == "warn"
}

reason := sprintf(
    "%d recent certificate(s) issued in last 90 days — within expected range",
    [input.recent_cert_count],
) if {
    decision == "pass"
}

reason := "No CT log entries found for this domain — may be a non-web domain or crt.sh was unavailable" if {
    decision == "skip"
    object.get(input, "total_count", null) != null
    input.total_count == 0
}
