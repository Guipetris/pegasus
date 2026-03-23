package compliance.ai.training_data_documented

import rego.v1

default decision := "skip"
default reason := "training data probe not configured or endpoint unreachable"

# Skip: endpoint not reachable / probe not configured for this target
decision := "skip" if {
    object.get(input, "endpoint_reachable", null) != null
    input.endpoint_reachable == false
}

# Pass: endpoint reachable and all key disclosure fields are present
decision := "pass" if {
    object.get(input, "endpoint_reachable", null) != null
    input.endpoint_reachable == true
    input.documentation_found == true
    input.has_data_sources == true
    input.has_preprocessing_description == true
    input.has_anonymization_info == true
}

# Warn: documentation found but missing data sources
decision := "warn" if {
    object.get(input, "endpoint_reachable", null) != null
    input.endpoint_reachable == true
    input.documentation_found == true
    input.has_data_sources == false
}

# Warn: documentation found but missing preprocessing description
decision := "warn" if {
    object.get(input, "endpoint_reachable", null) != null
    input.endpoint_reachable == true
    input.documentation_found == true
    input.has_preprocessing_description == false
}

# Warn: documentation found but missing anonymization info
decision := "warn" if {
    object.get(input, "endpoint_reachable", null) != null
    input.endpoint_reachable == true
    input.documentation_found == true
    input.has_anonymization_info == false
}

# Fail: endpoint reachable but no training data documentation found
decision := "fail" if {
    object.get(input, "endpoint_reachable", null) != null
    input.endpoint_reachable == true
    input.documentation_found == false
}

reason := sprintf(
    "Training data documentation complete (transparency score: %.2f) — data sources, preprocessing, and anonymization info present",
    [input.transparency_score]
) if { decision == "pass" }

reason := sprintf(
    "Training data documentation incomplete (transparency score: %.2f) — some disclosure fields are missing (EU AI Act Article 10)",
    [input.transparency_score]
) if { decision == "warn" }

reason := "No training data documentation found — EU AI Act Article 10 requires training data governance and disclosure" if {
    decision == "fail"
}
