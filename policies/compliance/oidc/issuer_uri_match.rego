package compliance.oidc.issuer_uri_match

import rego.v1

default decision := "skip"
default reason := "no OIDC discovery evidence, issuer not present, or target_host not available"

decision := "warn" if {
    object.get(input, "discovery_found", null) != null
    input.discovery_found == true
    input.issuer != null
    object.get(input, "target_host", null) != null
    not contains(input.issuer, input.target_host)
}

decision := "pass" if {
    object.get(input, "discovery_found", null) != null
    input.discovery_found == true
    input.issuer != null
    object.get(input, "target_host", null) != null
    contains(input.issuer, input.target_host)
}

reason := sprintf("issuer URI '%s' does not contain target host '%s' — possible misconfiguration or phishing risk", [input.issuer, input.target_host]) if { decision == "warn" }
reason := sprintf("issuer URI '%s' matches target host", [input.issuer]) if { decision == "pass" }
