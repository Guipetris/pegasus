package security.http.cors_origin_reflection

import rego.v1

# Detects CORS origin reflection — the server echoes back the attacker's Origin
# header in Access-Control-Allow-Origin, which is functionally equivalent to
# a wildcard for any origin that sends a request.
#
# Evidence input fields (from CorsProbeResult):
#   input.origin_reflected      bool — ACAO echoes the evil origin we sent
#   input.credentials_allowed   bool — ACAC: true was present
#
# Decision logic:
#   skip — no CORS probe evidence in input
#   fail — origin reflected AND credentials allowed (high severity)
#   warn — origin reflected WITHOUT credentials (medium severity)
#   pass — origin not reflected
#
# Standards: OWASP ASVS v4 §14.5.1, §14.5.3

default decision := "skip"
default reason := "no CORS probe evidence in input"

decision := "fail" if {
    object.get(input, "origin_reflected", null) != null
    input.origin_reflected == true
    input.credentials_allowed == true
}

decision := "warn" if {
    object.get(input, "origin_reflected", null) != null
    input.origin_reflected == true
    input.credentials_allowed == false
}

decision := "pass" if {
    object.get(input, "origin_reflected", null) != null
    input.origin_reflected == false
}

reason := "CRITICAL: Server reflects the request Origin in Access-Control-Allow-Origin with credentials enabled — any attacker origin can make credentialed cross-origin requests" if {
    decision == "fail"
}

reason := "Server reflects the request Origin in Access-Control-Allow-Origin — consider using an explicit origin allowlist instead" if {
    decision == "warn"
}

reason := "Origin reflection not detected — server does not echo back the request Origin header" if {
    decision == "pass"
}
