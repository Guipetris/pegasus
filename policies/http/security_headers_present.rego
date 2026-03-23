package compliance.http.security_headers_present

import rego.v1

default decision := "skip"
default reason := "no HTTP headers evidence in input"

decision := "pass" if {
    object.get(input, "headers", null) != null
    input.headers.strict_transport_security != null
    input.headers.x_content_type_options != null
    input.headers.x_frame_options != null
}

decision := "warn" if {
    object.get(input, "headers", null) != null
    input.headers.strict_transport_security != null
    some_optional_missing
}

decision := "fail" if {
    object.get(input, "headers", null) != null
    input.headers.strict_transport_security == null
}

some_optional_missing if {
    input.headers.x_content_type_options == null
}

some_optional_missing if {
    input.headers.x_frame_options == null
}

reason := "all critical security headers are present" if { decision == "pass" }
reason := "HSTS present but some recommended headers missing" if { decision == "warn" }
reason := "HSTS header is missing" if { decision == "fail" }
