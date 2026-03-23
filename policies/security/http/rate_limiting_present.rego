package security.http.rate_limiting_present

import rego.v1

# Checks whether an AI API endpoint enforces rate limiting.
#
# Evidence input fields (from RateLimitProbeResult):
#   input.endpoint_tested       bool  — false → skip (probe not configured)
#   input.rate_limited          bool  — HTTP 429 observed
#   input.has_retry_after       bool  — Retry-After header in 429 response
#   input.has_ratelimit_headers bool  — X-RateLimit-* headers observed
#
# Decision logic:
#   skip — probe not configured (endpoint_tested == false)
#   warn — endpoint tested, no HTTP 429 observed (no rate limiting detected)
#   pass — endpoint tested, HTTP 429 observed (rate limiting enforced)
#
# Standards:
#   OWASP ASVS v4 §11.1 — Denial of Service protection
#   ISO 42001 A.6.2.7 — AI system abuse prevention

default decision := "skip"
default reason := "rate limiting probe not configured for this endpoint"

decision := "warn" if {
    object.get(input, "endpoint_tested", null) != null
    input.endpoint_tested == true
    input.rate_limited == false
}

decision := "pass" if {
    object.get(input, "endpoint_tested", null) != null
    input.endpoint_tested == true
    input.rate_limited == true
}

reason := "Rate limiting probe ran but no HTTP 429 was observed — the endpoint may not enforce request throttling (OWASP ASVS §11.1, ISO 42001 A.6.2.7)" if {
    decision == "warn"
}

reason := sprintf("Rate limiting enforced — HTTP 429 observed; Retry-After present: %v, X-RateLimit headers present: %v", [input.has_retry_after, input.has_ratelimit_headers]) if {
    decision == "pass"
}
