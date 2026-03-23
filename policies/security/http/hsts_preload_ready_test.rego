package security.http.hsts_preload_ready_test

import rego.v1

import data.security.http.hsts_preload_ready

test_full_preload_passes if {
    result := hsts_preload_ready.decision with input as {
        "headers": {
            "strict_transport_security": "max-age=31536000; includeSubDomains; preload",
        },
    }
    result == "pass"
}

test_short_max_age_warns if {
    result := hsts_preload_ready.decision with input as {
        "headers": {
            "strict_transport_security": "max-age=86400; includeSubDomains",
        },
    }
    result == "warn"
}

test_missing_include_subdomains_warns if {
    result := hsts_preload_ready.decision with input as {
        "headers": {
            "strict_transport_security": "max-age=31536000",
        },
    }
    result == "warn"
}

test_no_hsts_skips if {
    result := hsts_preload_ready.decision with input as {
        "headers": {
            "x_content_type_options": "nosniff",
        },
    }
    result == "skip"
}

test_no_headers_skips if {
    result := hsts_preload_ready.decision with input as {}
    result == "skip"
}
