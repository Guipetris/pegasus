package compliance.tls.cabf_baseline_test

import rego.v1

import data.compliance.tls.cabf_baseline

test_compliant_cert_passes if {
    result := cabf_baseline.decision with input as {
        "certificates": [{
            "subject": "CN=compliant.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-12-01T00:00:00Z",
            "is_ca": false,
            "key_algorithm": "RSA",
            "key_size": 2048,
            "signature_algorithm": "SHA256withRSA",
        }],
    }
    result == "pass"
}

test_validity_over_398_days_fails if {
    result := cabf_baseline.decision with input as {
        "certificates": [{
            "subject": "CN=long-lived.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2027-01-01T00:00:00Z",
            "is_ca": false,
            "key_algorithm": "RSA",
            "key_size": 2048,
            "signature_algorithm": "SHA256withRSA",
        }],
    }
    result == "fail"
}

test_weak_rsa_1024_fails if {
    result := cabf_baseline.decision with input as {
        "certificates": [{
            "subject": "CN=weak-key.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-06-01T00:00:00Z",
            "is_ca": false,
            "key_algorithm": "RSA",
            "key_size": 1024,
            "signature_algorithm": "SHA256withRSA",
        }],
    }
    result == "fail"
}

test_sha1_signature_fails if {
    result := cabf_baseline.decision with input as {
        "certificates": [{
            "subject": "CN=sha1.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-06-01T00:00:00Z",
            "is_ca": false,
            "key_algorithm": "RSA",
            "key_size": 2048,
            "signature_algorithm": "SHA1withRSA",
        }],
    }
    result == "fail"
}

test_ec_p256_passes if {
    result := cabf_baseline.decision with input as {
        "certificates": [{
            "subject": "CN=ec.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-06-01T00:00:00Z",
            "is_ca": false,
            "key_algorithm": "EC",
            "key_size": 256,
            "signature_algorithm": "SHA384withECDSA",
        }],
    }
    result == "pass"
}

test_missing_key_fields_skips if {
    result := cabf_baseline.decision with input as {
        "certificates": [{
            "subject": "CN=legacy.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-06-01T00:00:00Z",
            "is_ca": false,
        }],
    }
    result == "skip"
}

test_ca_cert_with_sha1_allowed if {
    result := cabf_baseline.decision with input as {
        "certificates": [{
            "subject": "CN=Root CA",
            "issuer": "CN=Root CA",
            "not_before": "2020-01-01T00:00:00Z",
            "not_after": "2030-01-01T00:00:00Z",
            "is_ca": true,
            "key_algorithm": "RSA",
            "key_size": 4096,
            "signature_algorithm": "SHA1withRSA",
        }],
    }
    result == "pass"
}

test_intermediate_ca_with_long_validity_passes if {
    result := cabf_baseline.decision with input as {
        "certificates": [
            {
                "subject": "CN=leaf.example.com",
                "issuer": "CN=Intermediate CA",
                "not_before": "2025-01-01T00:00:00Z",
                "not_after": "2025-06-01T00:00:00Z",
                "is_ca": false,
                "key_algorithm": "RSA",
                "key_size": 2048,
                "signature_algorithm": "SHA256withRSA",
            },
            {
                "subject": "CN=Intermediate CA",
                "issuer": "CN=Root CA",
                "not_before": "2020-01-01T00:00:00Z",
                "not_after": "2030-01-01T00:00:00Z",
                "is_ca": true,
                "key_algorithm": "RSA",
                "key_size": 4096,
                "signature_algorithm": "SHA256withRSA",
            },
        ],
    }
    result == "pass"
}
