package compliance.oidc.secure_token_config

import rego.v1

default decision := "skip"
default reason := "no OIDC discovery evidence or not an OIDC service"

decision := "pass" if {
    object.get(input, "discovery_found", null) != null
    input.discovery_found == true
    not uses_weak_signing
}

decision := "warn" if {
    object.get(input, "discovery_found", null) != null
    input.discovery_found == true
    uses_weak_signing
}

uses_weak_signing if {
    some alg in input.id_token_signing_alg_values
    alg == "HS256"
}

uses_weak_signing if {
    some alg in input.id_token_signing_alg_values
    alg == "none"
}

reason := "OIDC token signing uses secure algorithms" if { decision == "pass" }
reason := "OIDC uses weak signing algorithm (HS256 or none)" if { decision == "warn" }
