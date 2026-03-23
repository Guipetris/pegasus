package compliance.tls.sha1_signature_prohibition_test

import rego.v1

import data.compliance.tls.sha1_signature_prohibition

test_sha256_leaf_passes if {
    result := sha1_signature_prohibition.decision with input as {
        "certificates": [{
            "subject": "CN=leaf.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-12-01T00:00:00Z",
            "is_ca": false,
            "signature_algorithm": "SHA256withRSA",
        }],
    }
    result == "pass"
}

test_sha1_leaf_fails if {
    result := sha1_signature_prohibition.decision with input as {
        "certificates": [{
            "subject": "CN=leaf.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-12-01T00:00:00Z",
            "is_ca": false,
            "signature_algorithm": "SHA1withRSA",
        }],
    }
    result == "fail"
}

test_sha1_root_ca_passes if {
    result := sha1_signature_prohibition.decision with input as {
        "certificates": [{
            "subject": "CN=Root CA",
            "issuer": "CN=Root CA",
            "not_before": "2010-01-01T00:00:00Z",
            "not_after": "2035-01-01T00:00:00Z",
            "is_ca": true,
            "signature_algorithm": "SHA1withRSA",
        }],
    }
    # Only a root CA — no non-root certs with sig_algo → skip (no non-root certs with field)
    # The root CA is exempt; there are no non-root certs to check, so skip.
    result == "skip"
}

test_sha1_root_ca_with_sha256_leaf_passes if {
    result := sha1_signature_prohibition.decision with input as {
        "certificates": [
            {
                "subject": "CN=leaf.example.com",
                "issuer": "CN=Root CA",
                "not_before": "2025-01-01T00:00:00Z",
                "not_after": "2025-12-01T00:00:00Z",
                "is_ca": false,
                "signature_algorithm": "SHA256withRSA",
            },
            {
                "subject": "CN=Root CA",
                "issuer": "CN=Root CA",
                "not_before": "2010-01-01T00:00:00Z",
                "not_after": "2035-01-01T00:00:00Z",
                "is_ca": true,
                "signature_algorithm": "SHA1withRSA",
            },
        ],
    }
    result == "pass"
}

test_missing_signature_algorithm_skips if {
    result := sha1_signature_prohibition.decision with input as {
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
    result := sha1_signature_prohibition.decision with input as {
        "certificates": [],
    }
    result == "skip"
}
