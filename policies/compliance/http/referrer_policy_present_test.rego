package compliance.http.referrer_policy_present_test

import rego.v1

import data.compliance.http.referrer_policy_present

test_strict_origin_passes if {
    result := referrer_policy_present.decision with input as {
        "headers": {
            "referrer_policy": "strict-origin-when-cross-origin",
        },
    }
    result == "pass"
}

test_no_referrer_passes if {
    result := referrer_policy_present.decision with input as {
        "headers": {
            "referrer_policy": "no-referrer",
        },
    }
    result == "pass"
}

test_unsafe_url_warns if {
    result := referrer_policy_present.decision with input as {
        "headers": {
            "referrer_policy": "unsafe-url",
        },
    }
    result == "warn"
}

test_missing_referrer_policy_fails if {
    result := referrer_policy_present.decision with input as {
        "headers": {
            "strict_transport_security": "max-age=31536000",
        },
    }
    result == "fail"
}

test_no_headers_skips if {
    result := referrer_policy_present.decision with input as {}
    result == "skip"
}
