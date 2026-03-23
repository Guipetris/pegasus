package compliance.http.permissions_policy_present_test

import rego.v1

import data.compliance.http.permissions_policy_present

test_permissions_policy_present_passes if {
    result := permissions_policy_present.decision with input as {
        "headers": {
            "permissions_policy": "camera=(), microphone=(), geolocation=()",
        },
    }
    result == "pass"
}

test_empty_permissions_policy_passes if {
    result := permissions_policy_present.decision with input as {
        "headers": {
            "permissions_policy": "",
        },
    }
    result == "pass"
}

test_missing_permissions_policy_fails if {
    result := permissions_policy_present.decision with input as {
        "headers": {
            "strict_transport_security": "max-age=31536000",
        },
    }
    result == "fail"
}

test_no_headers_skips if {
    result := permissions_policy_present.decision with input as {}
    result == "skip"
}
