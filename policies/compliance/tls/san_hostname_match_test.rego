package compliance.tls.san_hostname_match_test

import rego.v1

import data.compliance.tls.san_hostname_match

# ---------------------------------------------------------------------------
# skip: no certificates
# ---------------------------------------------------------------------------

test_no_certs_skips if {
    result := san_hostname_match.decision with input as {
        "certificates": [],
        "target": {"host": "example.com"},
    }
    result == "skip"
}

# ---------------------------------------------------------------------------
# skip: leaf cert has no SANs
# ---------------------------------------------------------------------------

test_no_sans_skips if {
    result := san_hostname_match.decision with input as {
        "certificates": [{
            "subject": "CN=example.com",
            "subject_alt_names": [],
            "is_ca": false,
        }],
        "target": {"host": "example.com"},
    }
    result == "skip"
}

# ---------------------------------------------------------------------------
# skip: no target host
# ---------------------------------------------------------------------------

test_no_target_host_skips if {
    result := san_hostname_match.decision with input as {
        "certificates": [{
            "subject": "CN=example.com",
            "subject_alt_names": ["example.com"],
            "is_ca": false,
        }],
        "target": {"host": null},
    }
    result == "skip"
}

# ---------------------------------------------------------------------------
# pass: exact match
# ---------------------------------------------------------------------------

test_exact_match_passes if {
    result := san_hostname_match.decision with input as {
        "certificates": [{
            "subject": "CN=example.com",
            "subject_alt_names": ["example.com", "www.example.com"],
            "is_ca": false,
        }],
        "target": {"host": "example.com"},
    }
    result == "pass"
}

# pass: case-insensitive match
test_case_insensitive_match_passes if {
    result := san_hostname_match.decision with input as {
        "certificates": [{
            "subject": "CN=Example.com",
            "subject_alt_names": ["Example.com"],
            "is_ca": false,
        }],
        "target": {"host": "example.com"},
    }
    result == "pass"
}

# ---------------------------------------------------------------------------
# pass: wildcard match
# ---------------------------------------------------------------------------

test_wildcard_match_passes if {
    result := san_hostname_match.decision with input as {
        "certificates": [{
            "subject": "CN=*.example.com",
            "subject_alt_names": ["*.example.com"],
            "is_ca": false,
        }],
        "target": {"host": "api.example.com"},
    }
    result == "pass"
}

test_wildcard_does_not_match_apex if {
    result := san_hostname_match.decision with input as {
        "certificates": [{
            "subject": "CN=*.example.com",
            "subject_alt_names": ["*.example.com"],
            "is_ca": false,
        }],
        "target": {"host": "example.com"},
    }
    # Apex does not match wildcard: RFC 2818 §3.1
    result == "warn"
}

test_wildcard_does_not_match_nested_subdomain if {
    result := san_hostname_match.decision with input as {
        "certificates": [{
            "subject": "CN=*.example.com",
            "subject_alt_names": ["*.example.com"],
            "is_ca": false,
        }],
        "target": {"host": "sub.api.example.com"},
    }
    # Wildcards only cover one label
    result == "warn"
}

# ---------------------------------------------------------------------------
# warn: hostname not in SANs
# ---------------------------------------------------------------------------

test_host_not_in_sans_warns if {
    result := san_hostname_match.decision with input as {
        "certificates": [{
            "subject": "CN=other.com",
            "subject_alt_names": ["other.com", "www.other.com"],
            "is_ca": false,
        }],
        "target": {"host": "example.com"},
    }
    result == "warn"
}

test_warn_reason_mentions_hostname if {
    result := san_hostname_match.reason with input as {
        "certificates": [{
            "subject": "CN=other.com",
            "subject_alt_names": ["other.com"],
            "is_ca": false,
        }],
        "target": {"host": "example.com"},
    }
    contains(result, "example.com")
}
