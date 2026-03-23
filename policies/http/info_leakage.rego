package compliance.http.info_leakage

import rego.v1

default decision := "skip"
default reason := "no HTTP info_leakage evidence in input"

decision := "fail" if {
    object.get(input, "info_leakage", null) != null
    input.info_leakage.x_powered_by != null
}

decision := "fail" if {
    object.get(input, "info_leakage", null) != null
    input.info_leakage.x_powered_by == null
    server := input.info_leakage.server
    server != null
    contains(server, "/")
}

decision := "warn" if {
    object.get(input, "info_leakage", null) != null
    input.info_leakage.x_powered_by == null
    server := input.info_leakage.server
    server != null
    not contains(server, "/")
}

decision := "pass" if {
    object.get(input, "info_leakage", null) != null
    input.info_leakage.x_powered_by == null
    input.info_leakage.server == null
}

reason := "X-Powered-By header reveals technology stack" if { decision == "fail"; input.info_leakage.x_powered_by != null }
reason := "Server header reveals version information" if { decision == "fail"; input.info_leakage.x_powered_by == null }
reason := "Server header present but no version details" if { decision == "warn" }
reason := "no information leakage detected" if { decision == "pass" }
