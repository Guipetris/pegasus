package security.oidc.implicit_flow_detection

import rego.v1

default decision := "skip"
default reason := "no OIDC discovery evidence or response_types_supported not present"

decision := "warn" if {
    object.get(input, "discovery_found", null) != null
    input.discovery_found == true
    input.response_types_supported != null
    some rt in input.response_types_supported
    rt == "token"
}

decision := "pass" if {
    object.get(input, "discovery_found", null) != null
    input.discovery_found == true
    input.response_types_supported != null
    not any_implicit_response_type
}

any_implicit_response_type if {
    some rt in input.response_types_supported
    rt == "token"
}

reason := "response_types_supported includes 'token' — implicit flow is enabled (deprecated per OAuth 2.1)" if { decision == "warn" }
reason := "no implicit flow response types detected — authorization code flow only" if { decision == "pass" }
