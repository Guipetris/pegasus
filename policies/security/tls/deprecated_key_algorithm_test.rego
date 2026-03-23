package security.tls.deprecated_key_algorithm_test

import rego.v1

import data.security.tls.deprecated_key_algorithm

test_rsa_passes if {
    result := deprecated_key_algorithm.decision with input as {
        "certificates": [{
            "subject": "CN=leaf.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-12-01T00:00:00Z",
            "is_ca": false,
            "key_algorithm": "RSA",
            "key_size": 2048,
        }],
    }
    result == "pass"
}

test_ecdsa_passes if {
    result := deprecated_key_algorithm.decision with input as {
        "certificates": [{
            "subject": "CN=leaf.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-12-01T00:00:00Z",
            "is_ca": false,
            "key_algorithm": "EC",
            "key_size": 256,
        }],
    }
    result == "pass"
}

test_dsa_fails if {
    result := deprecated_key_algorithm.decision with input as {
        "certificates": [{
            "subject": "CN=legacy.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-12-01T00:00:00Z",
            "is_ca": false,
            "key_algorithm": "DSA",
            "key_size": 1024,
        }],
    }
    result == "fail"
}

test_missing_key_algorithm_skips if {
    result := deprecated_key_algorithm.decision with input as {
        "certificates": [{
            "subject": "CN=leaf.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-12-01T00:00:00Z",
            "is_ca": false,
        }],
    }
    result == "skip"
}

test_empty_certificates_skips if {
    result := deprecated_key_algorithm.decision with input as {
        "certificates": [],
    }
    result == "skip"
}
