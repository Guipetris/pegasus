package compliance.semantic.schema_exposure_isolation_test

import rego.v1

import data.compliance.semantic.schema_exposure_isolation

test_schema_exposed_fails if {
    result := schema_exposure_isolation.decision with input as {
        "schema_exposure_detected": true,
    }
    result == "fail"
}

test_no_schema_exposure_passes if {
    result := schema_exposure_isolation.decision with input as {
        "schema_exposure_detected": false,
    }
    result == "pass"
}

test_missing_field_skips if {
    result := schema_exposure_isolation.decision with input as {}
    result == "skip"
}

test_missing_field_with_other_data_skips if {
    result := schema_exposure_isolation.decision with input as {
        "probe_type": "output_safety",
        "pii_patterns_detected": [],
    }
    result == "skip"
}
