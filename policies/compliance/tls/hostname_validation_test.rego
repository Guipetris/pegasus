package compliance.tls.hostname_validation_test

import rego.v1

import data.compliance.tls.hostname_validation

test_matching_hostname_passes if {
    result := hostname_validation.decision with input as {
        "target_host": "example.com",
        "certificates": [{
            "subject": "CN=example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-12-01T00:00:00Z",
            "is_ca": false,
        }],
    }
    result == "pass"
}

test_mismatched_hostname_warns if {
    result := hostname_validation.decision with input as {
        "target_host": "other.com",
        "certificates": [{
            "subject": "CN=example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-12-01T00:00:00Z",
            "is_ca": false,
        }],
    }
    result == "warn"
}

test_missing_target_host_skips if {
    result := hostname_validation.decision with input as {
        "certificates": [{
            "subject": "CN=example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-12-01T00:00:00Z",
            "is_ca": false,
        }],
    }
    result == "skip"
}

test_missing_certificates_skips if {
    result := hostname_validation.decision with input as {
        "target_host": "example.com",
        "certificates": [],
    }
    result == "skip"
}

test_hostname_substring_match_passes if {
    result := hostname_validation.decision with input as {
        "target_host": "example.com",
        "certificates": [{
            "subject": "CN=www.example.com, O=Example Inc",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-12-01T00:00:00Z",
            "is_ca": false,
        }],
    }
    result == "pass"
}
