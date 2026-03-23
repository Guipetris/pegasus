package compliance.tls.certificate_not_expired

import rego.v1

default decision := "fail"
default reason := "one or more certificates have expired"

# Pass if all certs are valid and none expiring within 30 days
decision := "pass" if {
    count(input.certificates) > 0
    all_valid
    not any_expiring_soon
}

# Warn if all valid but some expiring within 30 days
decision := "warn" if {
    count(input.certificates) > 0
    all_valid
    any_expiring_soon
}

reason := "all certificates are within validity period" if {
    decision == "pass"
}

reason := "certificate(s) expiring within 30 days" if {
    decision == "warn"
}

# Use evaluation_time (injected by the engine) as the reference point
eval_time_ns := time.parse_rfc3339_ns(input.evaluation_time)
thirty_days_ns := ((30 * 24) * 60) * 60 * 1000000000

all_valid if {
    every cert in input.certificates {
        time.parse_rfc3339_ns(cert.not_before) <= eval_time_ns
        time.parse_rfc3339_ns(cert.not_after) >= eval_time_ns
    }
}

any_expiring_soon if {
    some cert in input.certificates
    expires_ns := time.parse_rfc3339_ns(cert.not_after)
    expires_ns - eval_time_ns < thirty_days_ns
}
