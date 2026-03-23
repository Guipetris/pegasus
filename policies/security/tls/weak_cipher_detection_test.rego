package security.tls.weak_cipher_detection_test

import rego.v1

import data.security.tls.weak_cipher_detection

test_strong_config_passes if {
    result := weak_cipher_detection.decision with input as {
        "protocol_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "certificates": [{"key_algorithm": "RSA", "key_size": 4096, "subject": "CN=test", "issuer": "CN=test", "not_before": "2025-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "is_ca": true}],
    }
    result == "pass"
}

test_tls10_fails if {
    result := weak_cipher_detection.decision with input as {
        "protocol_version": "TLSv1.0",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "certificates": [{"key_algorithm": "RSA", "key_size": 2048, "subject": "CN=test", "issuer": "CN=test", "not_before": "2025-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "is_ca": true}],
    }
    result == "fail"
}

test_rc4_cipher_fails if {
    result := weak_cipher_detection.decision with input as {
        "protocol_version": "TLSv1.2",
        "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA",
        "certificates": [{"key_algorithm": "RSA", "key_size": 2048, "subject": "CN=test", "issuer": "CN=test", "not_before": "2025-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "is_ca": true}],
    }
    result == "fail"
}

test_weak_rsa_key_warns if {
    result := weak_cipher_detection.decision with input as {
        "protocol_version": "TLSv1.2",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "certificates": [{"key_algorithm": "RSA", "key_size": 1024, "subject": "CN=test", "issuer": "CN=test", "not_before": "2025-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "is_ca": true}],
    }
    result == "warn"
}

test_ec_p256_passes if {
    result := weak_cipher_detection.decision with input as {
        "protocol_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "certificates": [{"key_algorithm": "EC", "key_size": 256, "subject": "CN=test", "issuer": "CN=test", "not_before": "2025-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "is_ca": true}],
    }
    result == "pass"
}

test_null_cipher_fails if {
    result := weak_cipher_detection.decision with input as {
        "protocol_version": "TLSv1.2",
        "cipher_suite": "TLS_RSA_WITH_NULL_SHA256",
        "certificates": [{"key_algorithm": "RSA", "key_size": 2048, "subject": "CN=test", "issuer": "CN=test", "not_before": "2025-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "is_ca": true}],
    }
    result == "fail"
}

test_missing_input_skips if {
    result := weak_cipher_detection.decision with input as {
        "certificates": [{"key_algorithm": "RSA", "key_size": 2048, "subject": "CN=test", "issuer": "CN=test", "not_before": "2025-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "is_ca": true}],
    }
    result == "skip"
}
