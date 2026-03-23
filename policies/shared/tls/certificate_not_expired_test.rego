package compliance.tls.certificate_not_expired_test

import rego.v1

import data.compliance.tls.certificate_not_expired

# test_all_valid: all certs within validity, none expiring soon → decision == "pass"
# collected_at: 2024-06-15, not_after: 2025-06-15 (~365 days away, well beyond 30-day window)
test_all_valid if {
    result := certificate_not_expired.decision with input as {
        "envelope": {
            "raw_payload": {
                "certificates": [
                    {
                        "subject": "CN=example.com",
                        "issuer": "CN=Root CA",
                        "not_before": "2024-01-01T00:00:00Z",
                        "not_after": "2025-06-15T00:00:00Z",
                        "is_ca": false
                    },
                    {
                        "subject": "CN=Root CA",
                        "issuer": "CN=Root CA",
                        "not_before": "2020-01-01T00:00:00Z",
                        "not_after": "2030-01-01T00:00:00Z",
                        "is_ca": true
                    }
                ]
            },
            "collected_at": "2024-06-15T12:00:00Z"
        }
    }
    result == "pass"
}

# test_expired_cert: one cert with not_after in the past → decision == "fail"
# collected_at: 2024-06-15, not_after: 2024-01-01 (already expired)
test_expired_cert if {
    result := certificate_not_expired.decision with input as {
        "envelope": {
            "raw_payload": {
                "certificates": [
                    {
                        "subject": "CN=example.com",
                        "issuer": "CN=Root CA",
                        "not_before": "2023-01-01T00:00:00Z",
                        "not_after": "2024-01-01T00:00:00Z",
                        "is_ca": false
                    }
                ]
            },
            "collected_at": "2024-06-15T12:00:00Z"
        }
    }
    result == "fail"
}

# test_expiring_soon: cert expiring in 15 days → decision == "warn"
# collected_at: 2024-06-15T12:00:00Z, not_after: 2024-06-30T12:00:00Z (15 days away)
test_expiring_soon if {
    result := certificate_not_expired.decision with input as {
        "envelope": {
            "raw_payload": {
                "certificates": [
                    {
                        "subject": "CN=example.com",
                        "issuer": "CN=Root CA",
                        "not_before": "2024-01-01T00:00:00Z",
                        "not_after": "2024-06-30T12:00:00Z",
                        "is_ca": false
                    }
                ]
            },
            "collected_at": "2024-06-15T12:00:00Z"
        }
    }
    result == "warn"
}

# test_not_expiring_soon: cert expiring in 45 days → decision == "pass"
# collected_at: 2024-06-15T12:00:00Z, not_after: 2024-07-30T12:00:00Z (45 days away)
test_not_expiring_soon if {
    result := certificate_not_expired.decision with input as {
        "envelope": {
            "raw_payload": {
                "certificates": [
                    {
                        "subject": "CN=example.com",
                        "issuer": "CN=Root CA",
                        "not_before": "2024-01-01T00:00:00Z",
                        "not_after": "2024-07-30T12:00:00Z",
                        "is_ca": false
                    }
                ]
            },
            "collected_at": "2024-06-15T12:00:00Z"
        }
    }
    result == "pass"
}
