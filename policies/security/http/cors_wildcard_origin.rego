package security.http.cors_wildcard_origin

import rego.v1

# Detects dangerous CORS wildcard origin misconfigurations.
#
# Evidence input fields (from CorsProbeResult):
#   input.allows_credentials_with_wildcard  bool — ACAO: * AND ACAC: true
#   input.allows_arbitrary_origin           bool — ACAO: *
#
# Decision logic:
#   skip — no CORS evidence in input
#   fail — wildcard origin combined with credentials (W3C CORS spec violation)
#   warn — wildcard origin without credentials (lower risk, still poor practice)
#   pass — no wildcard origin detected
#
# Standards: OWASP ASVS v4 §14.5.1, W3C CORS Spec §6.2

default decision := "skip"
default reason := "no CORS probe evidence in input"

decision := "fail" if {
    object.get(input, "allows_credentials_with_wildcard", null) != null
    input.allows_credentials_with_wildcard == true
}

decision := "warn" if {
    object.get(input, "allows_arbitrary_origin", null) != null
    input.allows_arbitrary_origin == true
    input.allows_credentials_with_wildcard == false
}

decision := "pass" if {
    object.get(input, "allows_arbitrary_origin", null) != null
    input.allows_arbitrary_origin == false
}

reason := "CRITICAL: Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true — this is a W3C CORS spec violation that allows credentialed cross-origin requests from any site" if {
    decision == "fail"
}

reason := "Access-Control-Allow-Origin: * without credentials — wildcard CORS is poor practice; use an explicit origin allowlist" if {
    decision == "warn"
}

reason := "No wildcard CORS origin detected — ACAO header is absent or set to a specific origin" if {
    decision == "pass"
}
