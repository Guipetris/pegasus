package compliance.tls.wildcard_detection_test

import rego.v1

import data.compliance.tls.wildcard_detection

test_wildcard_cert_warns if {
    result := wildcard_detection.decision with input as {
        "certificates": [{
            "subject": "CN=*.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-12-01T00:00:00Z",
            "is_ca": false,
        }],
    }
    result == "warn"
}

test_no_wildcard_passes if {
    result := wildcard_detection.decision with input as {
        "certificates": [{
            "subject": "CN=www.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-12-01T00:00:00Z",
            "is_ca": false,
        }],
    }
    result == "pass"
}

test_wildcard_ca_not_flagged_as_leaf if {
    # A CA cert with wildcard-like subject — CAs are not leaf certs, so no warn.
    result := wildcard_detection.decision with input as {
        "certificates": [{
            "subject": "CN=*.internal CA",
            "issuer": "CN=Root CA",
            "not_before": "2020-01-01T00:00:00Z",
            "not_after": "2035-01-01T00:00:00Z",
            "is_ca": true,
        }],
    }
    result == "pass"
}

test_empty_certificates_skips if {
    result := wildcard_detection.decision with input as {
        "certificates": [],
    }
    result == "skip"
}
