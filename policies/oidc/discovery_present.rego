package compliance.oidc.discovery_present

import rego.v1

default decision := "skip"
default reason := "no OIDC discovery evidence or endpoint not found"

decision := "pass" if {
    object.get(input, "discovery_found", null) != null
    input.discovery_found == true
    input.issuer != null
    input.jwks_uri != null
}

decision := "warn" if {
    object.get(input, "discovery_found", null) != null
    input.discovery_found == true
    input.issuer == null
}

reason := "OIDC discovery endpoint found with issuer and JWKS URI" if { decision == "pass" }
reason := "OIDC discovery found but missing issuer field" if { decision == "warn" }
