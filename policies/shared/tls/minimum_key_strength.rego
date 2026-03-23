package compliance.tls.minimum_key_strength

import rego.v1

default decision := "skip"
default reason := "no TLS certificate evidence in input"

decision := "pass" if {
    object.get(input, "certificates", null) != null
    count(input.certificates) > 0
    count(weak_certs) == 0
}

decision := "fail" if {
    object.get(input, "certificates", null) != null
    count(input.certificates) > 0
    count(weak_certs) > 0
}

weak_certs contains cert if {
    some cert in input.certificates
    cert.key_type == "RSA"
    cert.key_bits < 2048
}

weak_certs contains cert if {
    some cert in input.certificates
    cert.key_type == "ECDSA"
    cert.key_bits < 256
}

reason := "all certificate keys meet minimum strength (RSA>=2048, ECDSA>=256)" if { decision == "pass" }
reason := sprintf("weak keys found in %d certificate(s)", [count(weak_certs)]) if { decision == "fail" }
