package compliance.tls.certificate_chain_valid

import rego.v1

default decision := "fail"
default reason := "certificate chain validation failed"

# Chain is valid if:
# 1. At least 2 certificates (leaf + at least one CA/intermediate)
# 2. Each cert[i].issuer matches cert[i+1].subject (chain links correctly)
# 3. The last certificate is a CA (is_ca == true)
#
# Note: real-world TLS chains often end at a cross-signed intermediate,
# not a self-signed root. The actual root CA is in the client trust store
# and not sent over TLS. So we check is_ca, not subject == issuer.

decision := "pass" if {
    count(input.certificates) >= 2
    chain_links_valid
    last_is_ca
}

reason := "certificate chain is valid: adequate length, correctly linked, terminates at CA" if {
    decision == "pass"
}

reason := "certificate chain too short: need at least leaf + CA" if {
    count(input.certificates) < 2
}

reason := "certificate chain links broken: issuer/subject mismatch between adjacent certs" if {
    count(input.certificates) >= 2
    not chain_links_valid
}

reason := "chain does not terminate at a CA certificate" if {
    count(input.certificates) >= 2
    chain_links_valid
    not last_is_ca
}

# Each cert's issuer must match the next cert's subject
chain_links_valid if {
    every i in numbers.range(0, count(input.certificates) - 2) {
        input.certificates[i].issuer == input.certificates[i + 1].subject
    }
}

# Last cert must be a CA (either self-signed root or cross-signed intermediate)
last_is_ca if {
    last := input.certificates[count(input.certificates) - 1]
    last.is_ca == true
}
