package security.http.csp_policy_strength

import rego.v1

default decision := "skip"
default reason := "no HTTP headers evidence or no CSP header in input"

decision := "fail" if {
    object.get(input, "headers", null) != null
    csp := input.headers.content_security_policy
    csp != null
    contains(csp, "unsafe-inline")
}

decision := "fail" if {
    object.get(input, "headers", null) != null
    csp := input.headers.content_security_policy
    csp != null
    not contains(csp, "unsafe-inline")
    contains(csp, "unsafe-eval")
}

decision := "warn" if {
    object.get(input, "headers", null) != null
    csp := input.headers.content_security_policy
    csp != null
    not contains(csp, "unsafe-inline")
    not contains(csp, "unsafe-eval")
    not contains(csp, "default-src")
}

decision := "pass" if {
    object.get(input, "headers", null) != null
    csp := input.headers.content_security_policy
    csp != null
    not contains(csp, "unsafe-inline")
    not contains(csp, "unsafe-eval")
    contains(csp, "default-src")
}

reason := "CSP contains 'unsafe-inline' — XSS protections weakened" if { decision == "fail"; contains(input.headers.content_security_policy, "unsafe-inline") }
reason := "CSP contains 'unsafe-eval' — XSS protections weakened" if { decision == "fail"; not contains(input.headers.content_security_policy, "unsafe-inline") }
reason := "CSP present but missing 'default-src' fallback directive" if { decision == "warn" }
reason := "CSP has default-src and no unsafe-* directives — policy is restrictive" if { decision == "pass" }
