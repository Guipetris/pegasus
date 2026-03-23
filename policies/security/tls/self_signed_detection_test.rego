package security.tls.self_signed_detection_test

import rego.v1

import data.security.tls.self_signed_detection

test_self_signed_non_ca_fails if {
    result := self_signed_detection.decision with input as {
        "certificates": [{
            "subject": "CN=myapp.internal",
            "issuer": "CN=myapp.internal",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2026-01-01T00:00:00Z",
            "is_ca": false,
        }],
    }
    result == "fail"
}

test_self_signed_ca_passes if {
    result := self_signed_detection.decision with input as {
        "certificates": [{
            "subject": "CN=Root CA",
            "issuer": "CN=Root CA",
            "not_before": "2020-01-01T00:00:00Z",
            "not_after": "2035-01-01T00:00:00Z",
            "is_ca": true,
        }],
    }
    result == "pass"
}

test_normal_two_cert_chain_passes if {
    result := self_signed_detection.decision with input as {
        "certificates": [
            {
                "subject": "CN=leaf.example.com",
                "issuer": "CN=Root CA",
                "not_before": "2025-01-01T00:00:00Z",
                "not_after": "2025-12-01T00:00:00Z",
                "is_ca": false,
            },
            {
                "subject": "CN=Root CA",
                "issuer": "CN=Root CA",
                "not_before": "2020-01-01T00:00:00Z",
                "not_after": "2035-01-01T00:00:00Z",
                "is_ca": true,
            },
        ],
    }
    result == "pass"
}

test_empty_certificates_skips if {
    result := self_signed_detection.decision with input as {
        "certificates": [],
    }
    result == "skip"
}
