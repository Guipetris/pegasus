package shared.tls.tls13_preferred_test

import rego.v1

import data.shared.tls.tls13_preferred

test_tls13_passes if {
    result := tls13_preferred.decision with input as {
        "protocol_version": "TLSv1.3",
        "certificates": [],
    }
    result == "pass"
}

test_tls12_warns if {
    result := tls13_preferred.decision with input as {
        "protocol_version": "TLSv1.2",
        "certificates": [],
    }
    result == "warn"
}

test_tls11_fails if {
    result := tls13_preferred.decision with input as {
        "protocol_version": "TLSv1.1",
        "certificates": [],
    }
    result == "fail"
}

test_tls10_fails if {
    result := tls13_preferred.decision with input as {
        "protocol_version": "TLSv1.0",
        "certificates": [],
    }
    result == "fail"
}

test_missing_protocol_version_skips if {
    result := tls13_preferred.decision with input as {
        "certificates": [],
    }
    result == "skip"
}
