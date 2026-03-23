package compliance.tls.maximum_chain_depth_test

import rego.v1

import data.compliance.tls.maximum_chain_depth

# Shared minimal cert used to build test chains.
_cert(cn) := {
    "subject": cn,
    "issuer": "CN=Root CA",
    "not_before": "2025-01-01T00:00:00Z",
    "not_after": "2025-12-01T00:00:00Z",
    "is_ca": false,
}

test_three_cert_chain_passes if {
    result := maximum_chain_depth.decision with input as {
        "certificates": [_cert("CN=a"), _cert("CN=b"), _cert("CN=c")],
    }
    result == "pass"
}

test_four_cert_chain_passes if {
    result := maximum_chain_depth.decision with input as {
        "certificates": [_cert("CN=a"), _cert("CN=b"), _cert("CN=c"), _cert("CN=d")],
    }
    result == "pass"
}

test_five_cert_chain_warns if {
    result := maximum_chain_depth.decision with input as {
        "certificates": [_cert("CN=a"), _cert("CN=b"), _cert("CN=c"), _cert("CN=d"), _cert("CN=e")],
    }
    result == "warn"
}

test_empty_certificates_skips if {
    result := maximum_chain_depth.decision with input as {
        "certificates": [],
    }
    result == "skip"
}
