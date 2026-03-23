package security.oidc.jwks_uri_https

import rego.v1

default decision := "skip"
default reason := "no OIDC discovery evidence or jwks_uri not present"

decision := "fail" if {
    object.get(input, "discovery_found", null) != null
    input.discovery_found == true
    input.jwks_uri != null
    not startswith(input.jwks_uri, "https://")
}

decision := "pass" if {
    object.get(input, "discovery_found", null) != null
    input.discovery_found == true
    input.jwks_uri != null
    startswith(input.jwks_uri, "https://")
}

reason := sprintf("jwks_uri uses insecure scheme: %s", [input.jwks_uri]) if { decision == "fail" }
reason := "jwks_uri uses HTTPS — key material served over secure transport" if { decision == "pass" }
