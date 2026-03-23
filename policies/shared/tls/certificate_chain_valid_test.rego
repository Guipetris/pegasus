package compliance.tls.certificate_chain_valid_test

import rego.v1

import data.compliance.tls.certificate_chain_valid

# test_valid_two_cert_chain: 2 certs where cert[0].issuer == cert[1].subject
# and cert[1] is self-signed → decision == "pass"
test_valid_two_cert_chain if {
    result := certificate_chain_valid.decision with input as {
        "envelope": {
            "raw_payload": {
                "certificates": [
                    {
                        "subject": "CN=example.com",
                        "issuer": "CN=Root CA",
                        "not_before": "2024-01-01T00:00:00Z",
                        "not_after": "2025-01-01T00:00:00Z",
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

# test_broken_chain: 2 certs where cert[0].issuer != cert[1].subject → decision == "fail"
test_broken_chain if {
    result := certificate_chain_valid.decision with input as {
        "envelope": {
            "raw_payload": {
                "certificates": [
                    {
                        "subject": "CN=example.com",
                        "issuer": "CN=Intermediate CA",
                        "not_before": "2024-01-01T00:00:00Z",
                        "not_after": "2025-01-01T00:00:00Z",
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
    result == "fail"
}

# test_single_self_signed: 1 self-signed cert → decision == "pass"
test_single_self_signed if {
    result := certificate_chain_valid.decision with input as {
        "envelope": {
            "raw_payload": {
                "certificates": [
                    {
                        "subject": "CN=Self-Signed",
                        "issuer": "CN=Self-Signed",
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

# test_empty_chain: no certificates → decision == "fail"
test_empty_chain if {
    result := certificate_chain_valid.decision with input as {
        "envelope": {
            "raw_payload": {
                "certificates": []
            },
            "collected_at": "2024-06-15T12:00:00Z"
        }
    }
    result == "fail"
}
