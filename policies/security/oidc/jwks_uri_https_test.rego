package security.oidc.jwks_uri_https_test

import rego.v1

import data.security.oidc.jwks_uri_https

test_https_jwks_uri_passes if {
    result := jwks_uri_https.decision with input as {
        "discovery_found": true,
        "issuer": "https://auth.example.com",
        "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
    }
    result == "pass"
}

test_http_jwks_uri_fails if {
    result := jwks_uri_https.decision with input as {
        "discovery_found": true,
        "issuer": "http://auth.example.com",
        "jwks_uri": "http://auth.example.com/.well-known/jwks.json",
    }
    result == "fail"
}

test_no_discovery_skips if {
    result := jwks_uri_https.decision with input as {
        "discovery_found": false,
    }
    result == "skip"
}

test_no_jwks_uri_skips if {
    result := jwks_uri_https.decision with input as {
        "discovery_found": true,
        "issuer": "https://auth.example.com",
    }
    result == "skip"
}

test_missing_discovery_field_skips if {
    result := jwks_uri_https.decision with input as {}
    result == "skip"
}
