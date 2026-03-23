package security.http.csp_policy_strength_test

import rego.v1

import data.security.http.csp_policy_strength

test_restrictive_csp_passes if {
    result := csp_policy_strength.decision with input as {
        "headers": {
            "content_security_policy": "default-src 'self'; script-src 'self'; object-src 'none'",
        },
    }
    result == "pass"
}

test_unsafe_inline_fails if {
    result := csp_policy_strength.decision with input as {
        "headers": {
            "content_security_policy": "default-src 'self'; script-src 'unsafe-inline'",
        },
    }
    result == "fail"
}

test_unsafe_eval_fails if {
    result := csp_policy_strength.decision with input as {
        "headers": {
            "content_security_policy": "default-src 'self'; script-src 'unsafe-eval'",
        },
    }
    result == "fail"
}

test_no_default_src_warns if {
    result := csp_policy_strength.decision with input as {
        "headers": {
            "content_security_policy": "script-src 'self'; object-src 'none'",
        },
    }
    result == "warn"
}

test_missing_csp_skips if {
    result := csp_policy_strength.decision with input as {
        "headers": {
            "x_content_type_options": "nosniff",
        },
    }
    result == "skip"
}

test_no_headers_skips if {
    result := csp_policy_strength.decision with input as {}
    result == "skip"
}
