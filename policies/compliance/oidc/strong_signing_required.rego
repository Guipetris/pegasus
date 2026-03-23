package compliance.oidc.strong_signing_required

import rego.v1

default decision := "skip"
default reason := "no OIDC discovery evidence or id_token_signing_alg_values not present"

decision := "fail" if {
    object.get(input, "discovery_found", null) != null
    input.discovery_found == true
    input.id_token_signing_alg_values != null
    count(input.id_token_signing_alg_values) > 0
    not has_asymmetric_alg
}

decision := "pass" if {
    object.get(input, "discovery_found", null) != null
    input.discovery_found == true
    input.id_token_signing_alg_values != null
    count(input.id_token_signing_alg_values) > 0
    has_asymmetric_alg
}

has_asymmetric_alg if {
    some alg in input.id_token_signing_alg_values
    not startswith(alg, "HS")
    alg != "none"
}

reason := "only symmetric signing algorithms (HS*) found — tokens cannot be independently verified by relying parties" if { decision == "fail" }
reason := "at least one asymmetric signing algorithm present — tokens can be independently verified" if { decision == "pass" }
