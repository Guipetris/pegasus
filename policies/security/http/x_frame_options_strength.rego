package security.http.x_frame_options_strength

import rego.v1

default decision := "skip"
default reason := "no HTTP headers evidence or no X-Frame-Options header in input"

decision := "fail" if {
    object.get(input, "headers", null) != null
    xfo := input.headers.x_frame_options
    xfo != null
    contains(xfo, "ALLOW-FROM")
}

decision := "warn" if {
    object.get(input, "headers", null) != null
    xfo := input.headers.x_frame_options
    xfo != null
    not contains(xfo, "ALLOW-FROM")
    xfo == "SAMEORIGIN"
}

decision := "pass" if {
    object.get(input, "headers", null) != null
    xfo := input.headers.x_frame_options
    xfo != null
    xfo == "DENY"
}

reason := "X-Frame-Options uses deprecated ALLOW-FROM directive — clickjacking protection unreliable" if { decision == "fail" }
reason := "X-Frame-Options is SAMEORIGIN — framing permitted from same origin" if { decision == "warn" }
reason := "X-Frame-Options is DENY — framing blocked entirely" if { decision == "pass" }
