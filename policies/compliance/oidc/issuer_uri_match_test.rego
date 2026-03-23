package compliance.oidc.issuer_uri_match_test

import rego.v1

import data.compliance.oidc.issuer_uri_match

test_matching_issuer_passes if {
    result := issuer_uri_match.decision with input as {
        "discovery_found": true,
        "issuer": "https://auth.example.com",
        "target_host": "auth.example.com",
    }
    result == "pass"
}

test_mismatch_issuer_warns if {
    result := issuer_uri_match.decision with input as {
        "discovery_found": true,
        "issuer": "https://attacker.example.net",
        "target_host": "auth.example.com",
    }
    result == "warn"
}

test_no_target_host_skips if {
    result := issuer_uri_match.decision with input as {
        "discovery_found": true,
        "issuer": "https://auth.example.com",
    }
    result == "skip"
}

test_no_discovery_skips if {
    result := issuer_uri_match.decision with input as {
        "discovery_found": false,
    }
    result == "skip"
}

test_missing_fields_skips if {
    result := issuer_uri_match.decision with input as {}
    result == "skip"
}
