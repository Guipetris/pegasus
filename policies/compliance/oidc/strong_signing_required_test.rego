package compliance.oidc.strong_signing_required_test

import rego.v1

import data.compliance.oidc.strong_signing_required

test_rs256_passes if {
    result := strong_signing_required.decision with input as {
        "discovery_found": true,
        "id_token_signing_alg_values": ["RS256"],
    }
    result == "pass"
}

test_es256_passes if {
    result := strong_signing_required.decision with input as {
        "discovery_found": true,
        "id_token_signing_alg_values": ["ES256"],
    }
    result == "pass"
}

test_mixed_algs_passes if {
    result := strong_signing_required.decision with input as {
        "discovery_found": true,
        "id_token_signing_alg_values": ["RS256", "HS256"],
    }
    result == "pass"
}

test_hs256_only_fails if {
    result := strong_signing_required.decision with input as {
        "discovery_found": true,
        "id_token_signing_alg_values": ["HS256"],
    }
    result == "fail"
}

test_hs_only_multiple_fails if {
    result := strong_signing_required.decision with input as {
        "discovery_found": true,
        "id_token_signing_alg_values": ["HS256", "HS384", "HS512"],
    }
    result == "fail"
}

test_no_discovery_skips if {
    result := strong_signing_required.decision with input as {
        "discovery_found": false,
    }
    result == "skip"
}

test_missing_alg_values_skips if {
    result := strong_signing_required.decision with input as {
        "discovery_found": true,
        "issuer": "https://auth.example.com",
    }
    result == "skip"
}
