package compliance.http.permissions_policy_present

import rego.v1

default decision := "skip"
default reason := "no HTTP headers evidence in input"

decision := "fail" if {
    object.get(input, "headers", null) != null
    input.headers.permissions_policy == null
}

decision := "pass" if {
    object.get(input, "headers", null) != null
    input.headers.permissions_policy != null
}

reason := "Permissions-Policy header is missing — browser features are unrestricted" if { decision == "fail" }
reason := "Permissions-Policy header is present" if { decision == "pass" }
