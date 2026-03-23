package compliance.semantic.schema_exposure_isolation

import rego.v1

default decision := "skip"
default reason := "no schema exposure evidence in input"

decision := "fail" if {
    object.get(input, "schema_exposure_detected", null) != null
    input.schema_exposure_detected == true
}

decision := "pass" if {
    object.get(input, "schema_exposure_detected", null) != null
    input.schema_exposure_detected == false
}

reason := "internal schema or tool definitions were exposed in AI responses — information disclosure risk" if { decision == "fail" }
reason := "no internal schema or tool definitions detected in AI responses" if { decision == "pass" }
