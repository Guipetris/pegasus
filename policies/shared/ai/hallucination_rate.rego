package shared.ai.hallucination_rate

import rego.v1

default decision := "skip"
default reason := "hallucination probe not configured or endpoint unreachable"

# Skip: endpoint not reachable / probe not configured for this target
decision := "skip" if {
    object.get(input, "endpoint_reachable", null) != null
    input.endpoint_reachable == false
}

# Pass: endpoint reachable and accuracy rate meets high threshold (>= 0.95)
decision := "pass" if {
    object.get(input, "endpoint_reachable", null) != null
    input.endpoint_reachable == true
    input.accuracy_rate >= 0.95
}

# Warn: accuracy rate acceptable but below high threshold (0.80 <= rate < 0.95)
decision := "warn" if {
    object.get(input, "endpoint_reachable", null) != null
    input.endpoint_reachable == true
    input.accuracy_rate >= 0.80
    input.accuracy_rate < 0.95
}

# Fail: endpoint reachable but accuracy rate below minimum threshold (< 0.80)
decision := "fail" if {
    object.get(input, "endpoint_reachable", null) != null
    input.endpoint_reachable == true
    input.accuracy_rate < 0.80
}

reason := sprintf(
    "Factual accuracy: %.0f%% correct (%d/%d questions)",
    [input.accuracy_rate * 100, input.correct_answers, input.questions_asked]
) if { decision == "pass" }

reason := sprintf(
    "Factual accuracy below target: %.0f%% correct — recommend review (threshold: 95%%)",
    [input.accuracy_rate * 100]
) if { decision == "warn" }

reason := sprintf(
    "Unacceptable hallucination rate: %.0f%% correct answers (minimum threshold: 80%%)",
    [input.accuracy_rate * 100]
) if { decision == "fail" }
