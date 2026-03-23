package security.ai.adversarial_robustness

import rego.v1

default decision := "skip"
default reason := "adversarial robustness probe not configured or endpoint unreachable"

# Skip: endpoint not reachable / probe not configured for this target
decision := "skip" if {
    object.get(input, "endpoint_reachable", null) != null
    input.endpoint_reachable == false
}

# Pass: endpoint reachable and robustness rate meets threshold (>= 0.8)
decision := "pass" if {
    object.get(input, "endpoint_reachable", null) != null
    input.endpoint_reachable == true
    input.robustness_rate >= 0.8
}

# Fail: endpoint reachable but robustness rate below threshold (< 0.8)
decision := "fail" if {
    object.get(input, "endpoint_reachable", null) != null
    input.endpoint_reachable == true
    input.robustness_rate < 0.8
}

reason := sprintf(
    "Adversarial robustness: %.0f%% graceful responses (%d/%d inputs handled correctly)",
    [input.robustness_rate * 100, input.graceful_responses, input.inputs_tested]
) if { decision == "pass" }

reason := sprintf(
    "Insufficient adversarial robustness: %.0f%% graceful responses (threshold: 80%%). Crashes/errors: %d",
    [input.robustness_rate * 100, input.crashes_or_errors]
) if { decision == "fail" }
