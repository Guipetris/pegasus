package security.http.x_frame_options_strength_test

import rego.v1

import data.security.http.x_frame_options_strength

test_deny_passes if {
    result := x_frame_options_strength.decision with input as {
        "headers": {
            "x_frame_options": "DENY",
        },
    }
    result == "pass"
}

test_sameorigin_warns if {
    result := x_frame_options_strength.decision with input as {
        "headers": {
            "x_frame_options": "SAMEORIGIN",
        },
    }
    result == "warn"
}

test_allow_from_fails if {
    result := x_frame_options_strength.decision with input as {
        "headers": {
            "x_frame_options": "ALLOW-FROM https://example.com",
        },
    }
    result == "fail"
}

test_missing_x_frame_options_skips if {
    result := x_frame_options_strength.decision with input as {
        "headers": {
            "strict_transport_security": "max-age=31536000",
        },
    }
    result == "skip"
}

test_no_headers_skips if {
    result := x_frame_options_strength.decision with input as {}
    result == "skip"
}
