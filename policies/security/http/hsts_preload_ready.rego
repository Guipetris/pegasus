package security.http.hsts_preload_ready

import rego.v1

default decision := "skip"
default reason := "no HTTP headers evidence or no HSTS header in input"

decision := "pass" if {
    object.get(input, "headers", null) != null
    hsts := input.headers.strict_transport_security
    hsts != null
    contains(hsts, "includeSubDomains")
    max_age_value(hsts) >= 31536000
}

decision := "warn" if {
    object.get(input, "headers", null) != null
    hsts := input.headers.strict_transport_security
    hsts != null
    not meets_preload_requirements(hsts)
}

meets_preload_requirements(hsts) if {
    contains(hsts, "includeSubDomains")
    max_age_value(hsts) >= 31536000
}

max_age_value(hsts) := val if {
    matches := regex.find_all_string_submatch_n(`max-age=(\d+)`, hsts, 1)
    count(matches) > 0
    val := to_number(matches[0][1])
}

reason := "HSTS includes includeSubDomains and max-age >= 1 year — preload ready" if { decision == "pass" }
reason := "HSTS present but does not meet preload requirements (requires includeSubDomains and max-age >= 31536000)" if { decision == "warn" }
