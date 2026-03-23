package compliance.http.referrer_policy_present

import rego.v1

default decision := "skip"
default reason := "no HTTP headers evidence in input"

decision := "fail" if {
    object.get(input, "headers", null) != null
    input.headers.referrer_policy == null
}

decision := "warn" if {
    object.get(input, "headers", null) != null
    input.headers.referrer_policy != null
    input.headers.referrer_policy == "unsafe-url"
}

decision := "pass" if {
    object.get(input, "headers", null) != null
    input.headers.referrer_policy != null
    input.headers.referrer_policy != "unsafe-url"
}

reason := "Referrer-Policy header is missing — referrer data may leak to third parties" if { decision == "fail" }
reason := "Referrer-Policy set to 'unsafe-url' — full URL sent as referrer to all origins" if { decision == "warn" }
reason := sprintf("Referrer-Policy is set to '%s'", [input.headers.referrer_policy]) if { decision == "pass" }
