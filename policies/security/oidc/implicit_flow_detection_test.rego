package security.oidc.implicit_flow_detection_test

import rego.v1

import data.security.oidc.implicit_flow_detection

test_code_only_passes if {
    result := implicit_flow_detection.decision with input as {
        "discovery_found": true,
        "response_types_supported": ["code"],
    }
    result == "pass"
}

test_code_id_token_passes if {
    result := implicit_flow_detection.decision with input as {
        "discovery_found": true,
        "response_types_supported": ["code", "code id_token"],
    }
    result == "pass"
}

test_token_response_type_warns if {
    result := implicit_flow_detection.decision with input as {
        "discovery_found": true,
        "response_types_supported": ["code", "token", "id_token"],
    }
    result == "warn"
}

test_no_discovery_skips if {
    result := implicit_flow_detection.decision with input as {
        "discovery_found": false,
    }
    result == "skip"
}

test_missing_response_types_skips if {
    result := implicit_flow_detection.decision with input as {
        "discovery_found": true,
        "issuer": "https://auth.example.com",
    }
    result == "skip"
}
