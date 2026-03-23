package compliance.tls.certificate_lifetime_short_test

import rego.v1

import data.compliance.tls.certificate_lifetime_short

test_normal_cert_passes if {
    # 90-day validity — well above 30-day threshold.
    result := certificate_lifetime_short.decision with input as {
        "certificates": [{
            "subject": "CN=leaf.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-04-01T00:00:00Z",
            "is_ca": false,
        }],
    }
    result == "pass"
}

test_15_day_cert_warns if {
    # 15-day validity — below 30-day threshold.
    result := certificate_lifetime_short.decision with input as {
        "certificates": [{
            "subject": "CN=leaf.example.com",
            "issuer": "CN=CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-01-16T00:00:00Z",
            "is_ca": false,
        }],
    }
    result == "warn"
}

test_ca_with_short_validity_not_flagged if {
    # CA certs are exempt — short validity on a CA should not warn.
    result := certificate_lifetime_short.decision with input as {
        "certificates": [{
            "subject": "CN=Short-Lived CA",
            "issuer": "CN=Root CA",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-01-10T00:00:00Z",
            "is_ca": true,
        }],
    }
    # No non-CA certs with date fields → skip.
    result == "skip"
}

test_missing_dates_skips if {
    result := certificate_lifetime_short.decision with input as {
        "certificates": [{
            "subject": "CN=leaf.example.com",
            "issuer": "CN=CA",
            "is_ca": false,
        }],
    }
    result == "skip"
}

test_empty_certificates_skips if {
    result := certificate_lifetime_short.decision with input as {
        "certificates": [],
    }
    result == "skip"
}
